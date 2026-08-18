// Package httpx is the single place reap builds outbound HTTP clients and
// TLS connections.
//
// Before this package existed there were six independent client/dialer
// construction sites (the MCP session, the OAuth well-known fetcher, the
// fingerprint runner, the plaintext-listener sweep, and two raw TLS dials),
// four of which hardcoded a 10s timeout and ignored --timeout entirely. That
// made flags like --proxy or --insecure impossible to honour: they would only
// ever apply to whichever code path remembered to check them.
//
// Everything that talks to a target now goes through a *Client built once per
// run and threaded down. That also means the rate limiter is genuinely global
// — a per-probe limiter would multiply the requested rate by the number of
// probes.
package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Config is the outbound-request policy for one reap run, assembled from CLI
// flags.
type Config struct {
	// Timeout bounds a single request/response round trip.
	Timeout time.Duration
	// Proxy is an optional proxy URL (http://, https://, socks5://) — the
	// flag that makes reap usable alongside Burp or mitmproxy.
	Proxy string
	// Insecure disables TLS certificate verification for target connections.
	// Note this is about reaching the target at all; the tls-cert-health
	// check deliberately inspects certificates without verifying them
	// regardless of this setting.
	Insecure bool
	// UserAgent overrides version.UserAgent when non-empty.
	UserAgent string
	// Headers are added to every request, unless the caller already set that
	// header on the specific request (per-probe headers win).
	Headers map[string]string
	// Retries is the number of additional attempts after a first failure.
	// Zero means try once. Only transport errors, 429 and 5xx are retried;
	// every request reap makes is a read, so retrying is always safe.
	Retries int
	// Delay is a fixed minimum pause between outbound requests.
	Delay time.Duration
	// RateLimit caps outbound requests per second. Zero means unlimited.
	RateLimit float64
}

// minInterval collapses Delay and RateLimit into the single spacing the
// limiter enforces. When both are set the stricter one wins.
func (c Config) minInterval() time.Duration {
	var fromRate time.Duration
	if c.RateLimit > 0 {
		fromRate = time.Duration(float64(time.Second) / c.RateLimit)
	}
	if c.Delay > fromRate {
		return c.Delay
	}
	return fromRate
}

// Client owns the shared rate limiter plus a configured *http.Client and TLS
// settings. Build one per run with New and pass it down.
type Client struct {
	cfg       Config
	userAgent string
	httpc     *http.Client
	lim       *limiter
}

// New validates cfg and builds the shared client. It returns an error only
// for input reap cannot act on (an unparseable proxy URL), so the CLI can
// report a usage problem instead of failing later mid-scan.
func New(cfg Config, defaultUserAgent string) (*Client, error) {
	ua := cfg.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.Insecure}, //nolint:gosec // opt-in via --insecure
		DialContext:         (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		TLSHandshakeTimeout: cfg.Timeout,
		// Recon fans out across many hosts and reuses each connection only a
		// handful of times; the stdlib defaults assume the opposite.
		MaxIdleConnsPerHost: 2,
	}
	if cfg.Proxy != "" {
		u, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid --proxy value %q: %w", cfg.Proxy, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid --proxy value %q: expected a URL like http://127.0.0.1:8080", cfg.Proxy)
		}
		transport.Proxy = http.ProxyURL(u)
	}

	c := &Client{
		cfg:       cfg,
		userAgent: ua,
		lim:       newLimiter(cfg.minInterval()),
	}
	c.httpc = &http.Client{
		Timeout:   cfg.Timeout,
		Transport: &roundTripper{base: transport, c: c},
		// Recon records what the endpoint actually answered. Following a
		// redirect would attribute the destination's headers to the target
		// URL, which quietly corrupts the CORS, rate-limit and
		// plaintext-transport observations.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// HTTP returns the configured client. Every caller shares one limiter.
func (c *Client) HTTP() *http.Client { return c.httpc }

// Timeout is the per-request timeout, for callers that need to derive their
// own deadlines from it.
func (c *Client) Timeout() time.Duration { return c.cfg.Timeout }

// UserAgent is the effective User-Agent string.
func (c *Client) UserAgent() string { return c.userAgent }

// TLSConfig returns the TLS settings for a raw dial to serverName.
//
// insecureForInspection exists because the tls-cert-health check must be able
// to complete a handshake against a certificate it intends to report as
// broken — refusing to connect would mean never producing the finding.
func (c *Client) TLSConfig(serverName string, insecureForInspection bool) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: c.cfg.Insecure || insecureForInspection, //nolint:gosec // see doc comment
	}
}

// DialTLS opens a rate-limited raw TLS connection, honouring --proxy is not
// possible here (a raw socket has no proxy semantics), so callers that need
// proxy support must use HTTP() instead.
func (c *Client) DialTLS(ctx context.Context, addr, serverName string, insecureForInspection bool) (net.Conn, error) {
	if err := c.lim.wait(ctx); err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: c.cfg.Timeout}
	return tls.DialWithDialer(d, "tcp", addr, c.TLSConfig(serverName, insecureForInspection))
}

// DialContext opens a rate-limited raw TCP connection.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := c.lim.wait(ctx); err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: c.cfg.Timeout}
	return d.DialContext(ctx, network, addr)
}

// roundTripper applies the User-Agent, the configured extra headers, the
// shared rate limit, and the retry policy. Per-request headers set by a probe
// always win over Config.Headers — a probe deliberately sending a hostile
// Origin or Host must not have it overwritten by a global default.
type roundTripper struct {
	base http.RoundTripper
	c    *Client
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", rt.c.userAgent)
	}
	for k, v := range rt.c.cfg.Headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	attempts := rt.c.cfg.Retries + 1
	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(req.Context(), backoff(attempt)); err != nil {
				return nil, err
			}
			// A retried POST needs its body rewound. http.NewRequest
			// populates GetBody for the in-memory body types reap uses.
			if req.Body != nil && req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return lastResp, lastErr
				}
				req.Body = body
			}
		}

		if err := rt.c.lim.wait(req.Context()); err != nil {
			return nil, err
		}

		resp, err := rt.base.RoundTrip(req)
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}
		lastResp, lastErr = resp, err
		if err == nil && attempt < attempts-1 {
			// Drain so the connection can be reused on the next attempt.
			resp.Body.Close()
			lastResp = nil
		}
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

// retryableStatus reports whether a status code is worth another attempt.
// 429 and 5xx are transient; everything else — including 401/403, which are
// findings in their own right — must be reported as observed.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func backoff(attempt int) time.Duration {
	d := time.Duration(attempt) * 250 * time.Millisecond
	if d > 2*time.Second {
		return 2 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// limiter spaces outbound requests by at least interval. A zero interval
// disables it entirely so the default path adds no synchronisation cost
// beyond one uncontended mutex.
type limiter struct {
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newLimiter(interval time.Duration) *limiter {
	return &limiter{interval: interval}
}

func (l *limiter) wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()

	return sleepCtx(ctx, time.Until(slot))
}

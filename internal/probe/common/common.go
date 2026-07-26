package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type PlaintextFallback struct {
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
}

func InspectTLS(ctx context.Context, target string) (*tls.ConnectionState, *x509.Certificate, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "https" {
		return nil, nil, fmt.Errorf("target URL is not https: %s", target)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("no peer certificate")
	}
	return &state, state.PeerCertificates[0], nil
}

func TLSVersionName(ver uint16) string {
	switch ver {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%x", ver)
	}
}

func IsWeakCipherSuite(id uint16) bool {
	switch id {
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return true
	default:
		return false
	}
}

func HasRateLimitHeader(headers http.Header) bool {
	for _, name := range []string{
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"RateLimit-Reset",
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"Retry-After",
		"RateLimit-Policy",
	} {
		if headers.Get(name) != "" {
			return true
		}
	}
	return false
}

func IsCORSWildcard(headers http.Header) (bool, bool) {
	acao := headers.Get("Access-Control-Allow-Origin")
	acac := headers.Get("Access-Control-Allow-Credentials")
	if acao != "*" {
		return false, false
	}
	return true, strings.EqualFold(acac, "true")
}

func DetectPlaintextListeners(ctx context.Context, targetURL string, paths []string) ([]PlaintextFallback, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	results := []PlaintextFallback{}

	for _, pth := range paths {
		path := pth
		if path == "" {
			path = "/"
		}
		httpURL := *u
		httpURL.Scheme = "http"
		httpURL.Path = path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL.String(), nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		contentType := resp.Header.Get("Content-Type")
		if resp.StatusCode == http.StatusOK || strings.Contains(strings.ToLower(contentType), "event-stream") {
			results = append(results, PlaintextFallback{
				Path:        httpURL.Path,
				StatusCode:  resp.StatusCode,
				ContentType: contentType,
			})
			if strings.Contains(strings.ToLower(string(body)), "jsonrpc") {
				results[len(results)-1].ContentType = contentType
			}
		}
	}
	return results, nil
}

func IsPlaintextURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.Scheme == "http"
}

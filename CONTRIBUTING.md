# Contributing

Thanks for considering it. Two contribution paths, roughly in order of how many PRs we expect:

## 1. New probe template (no Go required)

Read [`docs/WRITING_PROBES.md`](docs/WRITING_PROBES.md), drop a JSON file under `templates/<protocol>/`, and open a PR. Please include:

- A one-line explanation of what real-world misconfiguration this catches.
- The OWASP ASI reference(s) if genuinely applicable — don't force one.
- If you found the pattern in the wild (a real exposed endpoint, anonymized), say so in the PR description; that context helps reviewers a lot more than "seems like a good idea."

## 2. New protocol or Go probe

- New protocols live in `internal/probe/<protocol>/`, implementing the `Session` interface from `internal/probe/probe.go`. Start from `internal/probe/mcp/session.go` as the reference, or `internal/probe/generic/session.go` for the minimal shape. `docs/ARCHITECTURE.md` has a step-by-step checklist.
- New Go-level probes for an existing protocol go in that protocol's `checks.go`, implementing `probe.Probe`.
- **Check whether your idea is actually protocol-specific.** If it only needs a URL and an HTTP client (TLS, headers, CORS, redirects), it belongs in `internal/probe/transport` with `Protocol() == "*"`, where it runs against every protocol rather than one.
- Read the "Safety boundary" section of [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) first — `Session` must never expose a way to invoke a discovered capability, only to enumerate it. PRs that widen this boundary need a design discussion in an issue before code.

### Return the right thing from `Run`

This is the one contract reviewers will always check, because it's what makes a quiet report trustworthy:

| Situation | Return |
|---|---|
| Ran, nothing to report | `nil` |
| Correctly declined — wrong scheme, capability absent, nothing to test | `probe.NotApplicable("why")` |
| Couldn't complete — transport error, undecodable response | the real error |

Never swallow a failure with `return nil`. A probe that returns `nil` is asserting a negative result about the target.

### Don't put secrets in evidence

Findings end up in SARIF uploads, code-scanning dashboards, and pasted tickets. Session IDs, tokens, and credentials must be described (length, shape, character classes) rather than recorded. See `describeSessionIDShape` in `internal/probe/mcp/checks.go`.

## Before opening a PR

```bash
gofmt -l .        # must print nothing; CI fails otherwise
go vet ./...
go build ./...
go test -race ./...
```

Tests must be hermetic — bind `httptest` on loopback rather than reaching the network. If your change touches the handshake, transport, or pagination, verify it against the strict fixture too, since a permissive server will happily hide a bug:

```bash
python3 scripts/strict_mcp_server.py &
go run ./cmd/reap -t http://127.0.0.1:8099/mcp --authorized
```

## Releasing (maintainers)

Releases are fully automated by GoReleaser from a pushed git tag — nothing to bump by hand, the version is derived from the tag:

```sh
git tag v1.2.3
git push origin v1.2.3
```

This triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds cross-platform binaries, publishes a GitHub Release with checksums and a changelog, updates the `hackwither/homebrew-tap` cask, and pushes a multi-arch image to `ghcr.io/hackwither/reap`. See [`.goreleaser.yml`](.goreleaser.yml) for the exact build/publish steps. One-time setup (tap repo + `HOMEBREW_TAP_GITHUB_TOKEN` secret) only needs to happen once, before the first tag.

## Reporting exposures you find while testing this project

If you're testing reap itself against a real MCP server and it surfaces something concerning, that's a finding about *their* system, not ours — see the disclosure norms in [`SECURITY.md`](SECURITY.md). Please don't paste live, unredacted findings from third-party systems into GitHub issues here.

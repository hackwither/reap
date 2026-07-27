# Contributing

Thanks for considering it. Two contribution paths, roughly in order of how many PRs we expect:

## 1. New probe template (no Go required)

Read [`docs/WRITING_PROBES.md`](docs/WRITING_PROBES.md), drop a JSON file under `templates/<protocol>/`, and open a PR. Please include:

- A one-line explanation of what real-world misconfiguration this catches.
- The OWASP ASI reference(s) if genuinely applicable — don't force one.
- If you found the pattern in the wild (a real exposed endpoint, anonymized), say so in the PR description; that context helps reviewers a lot more than "seems like a good idea."

## 2. New protocol or Go probe

- New protocols live in `internal/probe/<protocol>/`, implementing the `Session` interface from `internal/probe/probe.go`. Start from `internal/probe/mcp/session.go` as the reference.
- New Go-level probes for an existing protocol go in that protocol's `checks.go`, implementing `probe.Probe`.
- Read the "Safety boundary" section of [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) first — `Session` must never expose a way to invoke a discovered capability, only to enumerate it. PRs that widen this boundary need a design discussion in an issue before code.

## Before opening a PR

```bash
gofmt -l .        # should print nothing
go vet ./...
go build ./...
go test ./...
```

## Reporting exposures you find while testing this project

If you're testing reap itself against a real MCP server and it surfaces something concerning, that's a finding about *their* system, not ours — see the disclosure norms in [`SECURITY.md`](SECURITY.md). Please don't paste live, unredacted findings from third-party systems into GitHub issues here.

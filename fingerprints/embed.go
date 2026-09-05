// Package fingerprints carries reap's built-in discovery fingerprints,
// embedded into the binary so a `go install`'d reap can identify protocols
// with no checkout on disk. The on-disk --fingerprints flag overrides this
// set; it does not require it.
package fingerprints

import "embed"

// FS holds every built-in JSON fingerprint, rooted so that
// discovery.LoadFingerprintFS can walk it exactly as it walks an on-disk
// directory.
//
//go:embed all:a2a all:mcp all:openapi
var FS embed.FS

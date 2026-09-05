// Package templates carries reap's built-in probe templates, embedded into
// the binary so a `go install`'d reap ships with them and needs no checkout
// on disk. The on-disk --templates flag overrides this set; it does not
// require it.
package templates

import "embed"

// FS holds every built-in JSON template, rooted so that template.LoadFS can
// walk it exactly as it walks an on-disk directory.
//
//go:embed all:mcp
var FS embed.FS

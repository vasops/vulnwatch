// Package imageref parses container image references and reads product
// versions from their tags.
package imageref

import (
	"path"
	"regexp"
	"strings"
)

// Ref is a parsed image reference.
type Ref struct {
	Registry string // docker.io when not given
	Path     string // library/postgres, keycloak/keycloak
	Tag      string
	Digest   string
}

// Parse splits an image reference such as "postgres:17.4",
// "quay.io/keycloak/keycloak:26.7.0" or "ghcr.io/x/y:v1@sha256:…" with the
// Docker defaults (docker.io, library/ for official images).
func Parse(s string) Ref {
	var r Ref
	s = strings.TrimSpace(s)
	s, r.Digest, _ = strings.Cut(s, "@")
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		s, r.Tag = s[:i], s[i+1:]
	}
	first, rest, found := strings.Cut(s, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Registry, s = first, rest
	}
	if r.Registry == "" || r.Registry == "index.docker.io" || r.Registry == "registry-1.docker.io" {
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && !strings.Contains(s, "/") {
		s = "library/" + s
	}
	r.Path = strings.ToLower(s)
	return r
}

// Repository is registry/path without tag or digest.
func (r Ref) Repository() string { return r.Registry + "/" + r.Path }

// String is the reference with its tag (digest left out).
func (r Ref) String() string {
	if r.Tag == "" {
		return r.Repository()
	}
	return r.Repository() + ":" + r.Tag
}

// Matches reports whether r is an image of the repository pattern p: the
// same path in any registry, or a mirror / proxy cache that prefixes the
// path (registry.example.com/dockerhub/library/postgres matches postgres).
func (r Ref) Matches(p Ref) bool {
	return r.Path == p.Path || strings.HasSuffix(r.Path, "/"+p.Path)
}

// MatchesPattern reports whether r matches a repository pattern with
// wildcards: "*" matches within one path segment, a final "**" one or more
// segments. Without a registry the pattern matches the path or its end, in
// any registry (mirrors, like Matches): "sig-storage/csi-*" matches
// registry.k8s.io/sig-storage/csi-attacher. With a registry it matches that
// registry from the start of the path: "registry.example.com/team/**".
func (r Ref) MatchesPattern(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	first, _, found := strings.Cut(pattern, "/")
	anchored := found && (strings.ContainsAny(first, ".:") || first == "localhost")
	p := Parse(pattern)
	pat := strings.Split(p.Path, "/")
	segs := strings.Split(r.Path, "/")
	if anchored {
		return p.Registry == r.Registry && globSegments(pat, segs)
	}
	for i := range segs {
		if globSegments(pat, segs[i:]) {
			return true
		}
	}
	return false
}

func globSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 1; i <= len(segs); i++ {
			if globSegments(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	ok, err := path.Match(pat[0], segs[0])
	return err == nil && ok && globSegments(pat[1:], segs[1:])
}

var (
	leading  = regexp.MustCompile(`^v?\d+(?:\.\d+)*(?:-(?:alpha|beta|rc)\.?\d*)?`)
	embedded = regexp.MustCompile(`(?:^|[^0-9A-Za-z.])(v?\d+\.\d+(?:\.\d+)*)`)
)

// Version reads the product version from the tag: "v3.9.1-distroless" →
// v3.9.1, "17.4-7-bullseye" → 17.4, "main-v1.80.0-stable" → v1.80.0,
// MinIO's RELEASE.2025-04-22T22-12-26Z as is. Empty when the tag holds no
// version (latest, a branch, a digest only).
func (r Ref) Version() string {
	t := r.Tag
	switch {
	case t == "":
		return ""
	case strings.HasPrefix(t, "RELEASE."):
		return t
	}
	if m := leading.FindString(t); m != "" {
		return m
	}
	if m := embedded.FindStringSubmatch(t); m != nil {
		return m[1]
	}
	return ""
}

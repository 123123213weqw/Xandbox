// Package pathchars recognizes only a fixed ASCII path-character language.
// It does not normalize a path, enforce a wire/path-size budget, inspect a file,
// prove ownership, or grant installation, publication or activation authority.
package pathchars

// Absolute matches exactly ^/[A-Za-z0-9_./-]+$. In particular, it rejects the
// bare root and all non-ASCII bytes, but accepts unclean paths such as // or /a/.
// Callers must retain their existing Clean, root, containment and other policy
// checks on the original string. No filesystem work or result cache is involved.
func Absolute(path string) bool {
	if len(path) < 2 || path[0] != '/' {
		return false
	}
	for i := 1; i < len(path); i++ {
		c := path[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '/' || c == '-' {
			continue
		}
		return false
	}
	return true
}

package installtxn

import (
	"strconv"
	"strings"
)

const stateFDInfoLimit = 4096
const stateOwnerFDLimit = 4096

// A closed regular-file fdinfo record, not an authority by itself. The caller
// must bind the actual procfs FD, original inode/path and pinned incarnation.
// Never accept multiple lock rows by deduplication or selecting the first row.
func stateFDInfoLockRecord(raw []byte, inode uint64) ([]byte, error) {
	if inode == 0 || len(raw) == 0 || len(raw) > stateFDInfoLimit || raw[len(raw)-1] != '\n' {
		return nil, ErrInventory
	}
	lines := strings.Split(string(raw[:len(raw)-1]), "\n")
	if len(lines) < 4 {
		return nil, ErrInventory
	}
	keys := [...]string{"pos:", "flags:", "mnt_id:", "ino:"}
	for i, key := range keys {
		parts := strings.Fields(lines[i])
		if !strings.HasPrefix(lines[i], key) || len(parts) != 2 || parts[0] != key {
			return nil, ErrInventory
		}
		text := parts[1]
		base, bits := 10, 64
		if i == 1 {
			base, bits = 8, 32
			if len(text) < 2 || text[0] != '0' {
				return nil, ErrInventory
			}
			text = text[1:]
		}
		n, e := strconv.ParseUint(text, base, bits)
		if e != nil || strconv.FormatUint(n, base) != text || i == 0 && n > 1<<63-1 || i == 2 && (n == 0 || n > 1<<31-1) || i == 3 && n != inode {
			return nil, ErrInventory
		}
	}
	if len(lines) == 4 {
		return nil, ErrConflict // An open descriptor without a lock is not proof.
	}
	for _, line := range lines[4:] {
		parts := strings.Fields(line)
		if !strings.HasPrefix(line, "lock:") || len(parts) < 2 || parts[0] != "lock:" {
			return nil, ErrInventory
		}
	}
	if len(lines) != 5 {
		return nil, ErrConflict
	}
	line := strings.TrimLeft(strings.TrimPrefix(lines[4], "lock:"), " \t")
	// Whitespace before the key is not a kernel regular-file fdinfo field.
	if line == lines[4] || line == "" {
		return nil, ErrInventory
	}
	return []byte(line + "\n"), nil
}

// Discovery names only, not proof that any FD holds a lock. Validate the whole
// bounded list before inspecting metadata; never truncate or ignore bad names.
func stateFDNames(names []string) error {
	if len(names) > stateOwnerFDLimit {
		return ErrInventory
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		n, e := strconv.ParseUint(name, 10, 31)
		if e != nil || strconv.FormatUint(n, 10) != name || seen[name] {
			return ErrInventory
		}
		seen[name] = true
	}
	return nil
}

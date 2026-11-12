//go:build linux

package installtxn

import (
	"os"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// The SOLE production caller already checked the COMPLETE result namespace
// before opening any row. This call freshly reads and pins that one actual
// file, then the unchanged terminal decoder/projection hashes those SAME private
// immutable bytes. Reuse only that locally computed raw digest in the original
// state frame; never accept an external digest, cached result or prior file/FD.
// Every later file/pass/operation still rereads and rehashes in full.
func (r *stateInventoryReader) retainedResult(dir *os.File, name string, p *sandbox.ResultInspectionProjection) (sandbox.ResultRecordInspection, error) {
	path := "results/" + name
	raw, st, e := r.fileBytes(dir, name, sandbox.MaxResultRecordBytes, false)
	if e != nil {
		return sandbox.ResultRecordInspection{}, e
	}
	row, e := p.Add(name[:32], raw)
	if e != nil {
		// Preserve even the old private failed-prefix frame/count, though no
		// public caller may return or resume a rejected inventory prefix.
		r.bind(path, st, raw)
		r.view.Files++
		return sandbox.ResultRecordInspection{}, e
	}
	// EXACT original r.bind frame and field order. RawSHA256 was computed by
	// p.Add above from this fresh raw slice, not supplied by a caller. Its V2
	// checksum/canonicalness/order/count/byte proofs remain independent.
	r.hash.Write(encode(struct {
		Path   string
		Entry  stateEntryIdentity
		SHA256 string
	}{path, stateEntry(st), row.RawSHA256}))
	r.view.Files++
	return row, nil
}

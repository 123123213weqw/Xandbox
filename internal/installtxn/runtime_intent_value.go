package installtxn

import (
	"bytes"
	"encoding/json"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Only these existing closed, comparable intents; not arbitrary caller schemas.
// The reader's SAME pure semantic policy and original trusted bounded file read
// remain mandatory. This helper has no filesystem or lifetime authority.
type canonicalRuntimeIntent interface {
	runtimeDrainIntent | runtimeStopIntent
}

// Unlike the four work/close decoders, these readers return populated values
// WITH errors. Every rejected fresh candidate therefore executes the EXACT old
// strict expression on the ORIGINAL zero target, retaining partial/error output.
// A nonzero target always uses the old merge expression, including references.
func canonicalRuntimeIntentValue[T canonicalRuntimeIntent](data []byte, out *T) bool {
	if out == nil {
		return false
	}
	var zero T
	if *out == zero && len(data) > 1 && data[0] == '{' && data[len(data)-1] == '\n' &&
		bytes.Count(data, []byte{'{'})+bytes.Count(data, []byte{'['}) <= 64 {
		var candidate T
		if json.Unmarshal(data, &candidate) == nil && bytes.Equal(data, encode(candidate)) {
			*out = candidate
			return true
		}
	}
	return strictjson.Decode(data, out) == nil && bytes.Equal(data, encode(out))
}

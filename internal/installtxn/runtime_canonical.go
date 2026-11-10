package installtxn

import (
	"bytes"
	"encoding/json"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Compile-time closed, comparable record union: no maps/slices/interfaces or
// generic caller-selected schema may reach the fast path. A schema-contract
// test also rejects custom JSON methods, ambiguous tags and reference growth.
type canonicalRuntimeRecord interface {
	runtimeWorkStopIntent | runtimeWorkCompletion | runtimeCloseIntent | runtimeCloseCompletion
}

// Exact canonical re-encoding already rejects every unknown/duplicate/folded
// key, alternate spelling/whitespace/order, lossy UTF-8, null/type/coercion and
// trailing-value form. For THESE closed schemas it subsumes the token pre-pass.
// This is syntax/canonicalness ONLY; every original authority/value validator,
// MaxPlan file read, mode/link/stat/inventory/hash and live proof stays separate.
func canonicalRuntimeValue[T canonicalRuntimeRecord](data []byte, out *T) bool {
	if out == nil {
		return false
	}
	var zero T
	if *out != zero {
		// Preserve existing merge-into-nonzero behavior exactly, including reference
		// semantics. Do not invent a cache or silently accept a lighter policy.
		return strictjson.Decode(data, out) == nil && bytes.Equal(data, encode(out))
	}
	if len(data) == 0 || data[0] != '{' || data[len(data)-1] != '\n' {
		return false
	}
	var candidate T
	if json.Unmarshal(data, &candidate) != nil || !bytes.Equal(data, encode(candidate)) {
		return false
	}
	*out = candidate
	return true
}

// Only the four actual journal types use the canonical fast path. Any other
// private caller retains the original strict expression; there is no new
// exported decoder or arbitrary-schema fallback to permissive json.Unmarshal.
func decodeCanonicalRuntime(data []byte, out any) bool {
	switch value := out.(type) {
	case *runtimeWorkStopIntent:
		return canonicalRuntimeValue(data, value)
	case *runtimeWorkCompletion:
		return canonicalRuntimeValue(data, value)
	case *runtimeCloseIntent:
		return canonicalRuntimeValue(data, value)
	case *runtimeCloseCompletion:
		return canonicalRuntimeValue(data, value)
	default:
		return strictjson.Decode(data, out) == nil && bytes.Equal(data, encode(out))
	}
}

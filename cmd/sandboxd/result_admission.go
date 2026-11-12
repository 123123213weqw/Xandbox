package main

import "github.com/123123213weqw/Xandbox/internal/sandbox"

// Same explicit opt-in/defaults as the ordinary store-opening branch. Zero
// means disabled; never infer retention from files, node budgets or old data.
func requestedResultLimits(bytes, tenant int64, records int) sandbox.ResultLimits {
	if bytes == 0 {
		return sandbox.ResultLimits{}
	}
	if tenant == 0 {
		tenant = min(16<<20, bytes)
	}
	if records == 0 {
		records = 4096
	}
	return sandbox.ResultLimits{Bytes: bytes, TenantBytes: tenant, Records: records}
}

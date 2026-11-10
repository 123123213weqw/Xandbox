package nodecontrol

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestMaintenanceStrictHTTPRequestsHaveNoReleaseOrLegacyFallback(t *testing.T) {
	root, _, c, _ := maintenanceController(t)
	h := controlHandler(c, func() sandbox.Stats { return sandbox.Stats{} })
	data, _ := json.Marshal(maintenanceRequest(c.Status().Committed))
	valid := string(data)
	before := maintenanceTree(t, root)
	for n, tc := range []struct {
		method, path, body, header, value string
		want                              int
	}{
		{"GET", maintenancePath, "", "", "", 200},
		{"GET", maintenancePath, "x", "", "", 400},
		{"GET", maintenancePath + "?force=1", "", "", "", 400},
		{"POST", maintenancePath, valid, "Authorization", "Bearer tenant", 400},
		{"POST", maintenancePath, valid, "Origin", "https://tenant.invalid", 400},
		{"POST", maintenancePath, valid, "Content-Type", "text/plain", 415},
		{"POST", maintenancePath, strings.Replace(valid, `"version":1`, `"version":2`, 1), "", "", 400},
		{"POST", maintenancePath, strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1), "", "", 400},
		{"POST", maintenancePath, strings.Replace(valid, `"version":1`, `"version":1,"release":true`, 1), "", "", 400},
		{"POST", maintenancePath, valid + valid, "", "", 400},
		{"POST", maintenancePath, strings.Repeat("x", MaxCommandBytes+1), "", "", 413},
		{"DELETE", maintenancePath, "", "", "", 405},
		{"POST", maintenancePath + "/release", valid, "", "", 404},
	} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatal(w.Code, tc.want, w.Body.String())
			}
			if !equalMaintenanceTree(before, maintenanceTree(t, root)) || !c.Status().AdmissionOpen {
				t.Fatal("invalid command mutated admission")
			}
		})
	}
	r := httptest.NewRequest("POST", maintenancePath, strings.NewReader(valid))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var reply MaintenanceReply
	if json.Unmarshal(w.Body.Bytes(), &reply) != nil || !reply.valid() || reply.Record == nil || reply.Control.AdmissionOpen {
		t.Fatal(w.Body.String())
	}
	cmd, _ := json.Marshal(command(reply.Control.Committed, "d"))
	r = httptest.NewRequest("POST", "/v1/node/resume", strings.NewReader(string(cmd)))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"MAINTENANCE"`) {
		t.Fatal("ordinary resume bypass", w.Code, w.Body.String())
	}
}

func TestMaintenanceHTTPUnsupportedStoreDoesNotDrainOrInventAnOwner(t *testing.T) {
	c, e := New(&memoryStore{state: initialState()}, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(t.Context())
	h := controlHandler(c, func() sandbox.Stats { return sandbox.Stats{} })
	data, _ := json.Marshal(maintenanceRequest(c.Status().Committed))
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, maintenancePath, strings.NewReader(map[string]string{"GET": "", "POST": string(data)}[method]))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 501 || !c.Status().AdmissionOpen || c.maintenance != nil {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

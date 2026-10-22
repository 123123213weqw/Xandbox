package strictjson

import (
	"strings"
	"testing"
)

func TestStrictObjects(t *testing.T) {
	type target struct {
		Name   string `json:"name"`
		Values []int  `json:"values"`
		Limits struct {
			MaxJobs int `json:"max_jobs"`
		} `json:"limits"`
	}
	for _, input := range []string{
		``, `null`, `[]`, `{} {}`, `{"name":"one","name":"two"}`,
		`{"name":"one","NAME":"two"}`, `{"unknown":true}`, `{"values":[1,]}`,
		`{"limits":{"max_jobs":2,"MAX_JOBſ":3}}`, `{"name":false}`,
		`{"values":` + strings.Repeat("[", 70) + `1` + strings.Repeat("]", 70) + `}`,
	} {
		var out target
		if err := Decode([]byte(input), &out); err == nil {
			t.Errorf("accepted ambiguous/invalid JSON: %.100s", input)
		}
	}
	var out target
	if err := Decode([]byte(`{"name":"ok","values":[1,2],"limits":{"max_jobs":2}}`), &out); err != nil || out.Name != "ok" || len(out.Values) != 2 {
		t.Fatalf("valid JSON: %+v %v", out, err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"a":{"A":1,"a":2}}`, `{"a":[null,true]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 65_536 {
			t.Skip()
		}
		var out map[string]any
		_ = Decode([]byte(data), &out)
	})
}

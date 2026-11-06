//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCreationCostDeliveryPayloadRetainsOriginalJSONAndWhitespace(t *testing.T) {
	original := []byte(`{"schema":3,"scope":"checkpoint","raw":"e30=","value":42}`)
	before := bytes.Clone(original)
	padded, err := costDeliveryMaximumPayload(original)
	if err != nil || len(padded) != 1<<20 || !bytes.Equal(padded[:len(original)], original) || !bytes.Equal(original, before) {
		t.Fatal("original prefix/length changed", err)
	}
	for _, b := range padded[len(original):] {
		if b != ' ' {
			t.Fatal("not canonical ASCII JSON whitespace")
		}
	}
	var a, b any
	if json.Unmarshal(original, &a) != nil || json.Unmarshal(padded, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("underlying JSON value changed")
	}
	padded[0] = '['
	if !bytes.Equal(original, before) {
		t.Fatal("output aliases original bytes")
	}
}
func TestCreationCostDeliveryPayloadRejectsInvalidOrOversizedJSON(t *testing.T) {
	huge := append([]byte(`{"x":"`), bytes.Repeat([]byte{'x'}, 1<<20)...)
	huge = append(huge, []byte(`"}`)...)
	for _, input := range [][]byte{nil, {}, []byte("bad"), []byte(" "), []byte("{}trailing"), append([]byte("{}"), 0xff), huge} {
		before := bytes.Clone(input)
		if out, err := costDeliveryMaximumPayload(input); err == nil || out != nil || !bytes.Equal(before, input) {
			t.Fatal("invalid input accepted or rewritten")
		}
	}
}
func TestCreationCostDeliveryPayloadAtExistingMaximumNeverTrims(t *testing.T) {
	original := append([]byte("{}"), bytes.Repeat([]byte{' '}, (1<<20)-2)...)
	padded, err := costDeliveryMaximumPayload(original)
	if err != nil || len(padded) != 1<<20 || !bytes.Equal(padded, original) {
		t.Fatal("existing maximum altered", err)
	}
	if _, err = costDeliveryMaximumPayload(append(original, ' ')); err == nil {
		t.Fatal("maximum raised or oversized input trimmed")
	}
}
func TestCreationCostDeliveryPayloadUnchanged512FrameBounds(t *testing.T) {
	padded, err := costDeliveryMaximumPayload([]byte(`{"schema":3,"scope":"checkpoint"}`))
	if err != nil {
		t.Fatal(err)
	}
	frames, err := costPackets("checkpoint", padded)
	if err != nil || len(frames) != 512 {
		t.Fatal("existing maximum framing changed", err)
	}
	sum := sha256.Sum256(padded)
	want := hex.EncodeToString(sum[:])
	var recovered []byte
	for i, wire := range frames {
		if len(wire) > 4096 {
			t.Fatal("existing row limit raised")
		}
		var row struct {
			Scope  string `json:"scope"`
			Index  int    `json:"index"`
			Chunks int    `json:"chunks"`
			Bytes  int    `json:"bytes"`
			SHA    string `json:"sha256"`
			Data   string `json:"data"`
		}
		if json.Unmarshal(wire, &row) != nil || row.Scope != "checkpoint" || row.Index != i || row.Chunks != 512 || row.Bytes != 1<<20 || row.SHA != want {
			t.Fatal("original frame identity changed")
		}
		b, e := base64.StdEncoding.DecodeString(row.Data)
		if e != nil || len(b) != 2048 {
			t.Fatal("original chunk bound changed")
		}
		recovered = append(recovered, b...)
	}
	if !bytes.Equal(recovered, padded) {
		t.Fatal("original producer bytes were not delivered by framing")
	}
	if _, err = costPackets("bad", padded); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if _, err = costPackets("checkpoint", append(padded, ' ')); err == nil {
		t.Fatal("existing wire maximum raised")
	}
}

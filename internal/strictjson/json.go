// Package strictjson decodes bounded, unambiguous JSON configuration and API objects.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

func Decode(data []byte, out any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("expected a JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := value(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("expected exactly one JSON object")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func value(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			key = foldKey(key)
			if seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case json.Delim('['):
		for d.More() {
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	}
	return nil
}

// Match encoding/json's Unicode simple-fold equivalence (including long S
// and Kelvin sign), not just ASCII case or strings.ToLower.
func foldKey(key string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		return smallest
	}, key)
}

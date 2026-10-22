// Package guestwire defines a bounded, single-call guest control protocol.
// It contains no command execution implementation or host fallback.
package guestwire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const (
	Version     = 1
	Port        = 900     // Privileged guest port; only peer CID 2 is accepted.
	MaxRequest  = 262_144 // Includes worst-case six-byte JSON escaping of argv.
	MaxResponse = 524_288
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Request struct {
	Version        int         `json:"version"`
	Operation      string      `json:"operation"`
	Ref            sandbox.Ref `json:"ref"`
	ExecutionID    string      `json:"execution_id,omitempty"`
	Argv           []string    `json:"argv,omitempty"`
	TimeoutMS      int         `json:"timeout_ms,omitempty"`
	MaxOutputBytes int         `json:"max_output_bytes,omitempty"`
}

func (r Request) Valid() bool {
	if r.Version != Version || !idPattern.MatchString(r.Ref.ID) || !idPattern.MatchString(r.Ref.Generation) {
		return false
	}
	switch r.Operation {
	case "health":
		return r.ExecutionID == "" && len(r.Argv) == 0 && r.TimeoutMS == 0 && r.MaxOutputBytes == 0
	case "exec":
		if !idPattern.MatchString(r.ExecutionID) || len(r.Argv) < 1 || len(r.Argv) > 128 || r.Argv[0] == "" || r.TimeoutMS < 1 || r.TimeoutMS > 60_000 || r.MaxOutputBytes < 1 || r.MaxOutputBytes > 65_536 {
			return false
		}
		size := 0
		for _, arg := range r.Argv {
			size += len(arg)
			for _, b := range []byte(arg) {
				if b == 0 {
					return false
				}
			}
		}
		return size <= 32_768
	default:
		return false
	}
}

type Response struct {
	Version      int            `json:"version"`
	Ref          sandbox.Ref    `json:"ref"`
	ExecutionID  string         `json:"execution_id,omitempty"`
	Status       string         `json:"status"`
	Output       sandbox.Output `json:"output"`
	Error        string         `json:"error,omitempty"`
	BootID       string         `json:"boot_id,omitempty"`
	ActiveGroups *int           `json:"active_execution_groups,omitempty"`
}

func Read(r io.Reader, limit uint32, out any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > limit {
		return errors.New("guest frame exceeds protocol bounds")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return strictjson.Decode(data, out)
}

func Write(w io.Writer, limit uint32, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || uint64(len(data)) > uint64(limit) {
		return errors.New("guest frame exceeds protocol bounds")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

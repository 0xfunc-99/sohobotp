// Package bundle reads the enrolment settings the portal can add to the end of the agent
// program ("Download agent" page): portal address, enrolment token, portal key pin and the
// portal's CA certificate. A downloaded agent then enrols with "install" and no options.
//
// Layout of a program with settings (nothing is compiled: the portal only appends):
//
//	program bytes | settings (JSON) | SHA-256 of the settings (32) | settings length (4, big endian) | magic (16)
//
// The settings contain the enrolment token: the installed copy of the program never keeps
// them (ProgramSize gives the length to copy).
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Magic ends a program that carries settings.
const Magic = "SOHOBOTP-BUNDLE1"

const footerSize = sha256.Size + 4 + len(Magic)

// MaxSettings bounds the settings block (a CA bundle is a few kilobytes).
const MaxSettings = 256 * 1024

// Settings is what an enrolment needs.
type Settings struct {
	Version int    `json:"v"`
	Portal  string `json:"portal"`
	Token   string `json:"token"`
	Pin     string `json:"pin"`
	CAPEM   string `json:"ca_pem,omitempty"`
}

// ErrDamaged is returned when a program ends with the magic but its settings do not check.
var ErrDamaged = errors.New("the enrolment settings built into this program are damaged: download the agent again from the portal")

// Read returns the settings built into the program at path (nil when it has none) and the
// length of the program itself, without the settings.
func Read(path string) (*Settings, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if size < int64(footerSize) {
		return nil, size, nil
	}
	footer := make([]byte, footerSize)
	if _, err := f.ReadAt(footer, size-int64(footerSize)); err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(footer[sha256.Size+4:], []byte(Magic)) {
		return nil, size, nil
	}
	length := int64(binary.BigEndian.Uint32(footer[sha256.Size : sha256.Size+4]))
	if length == 0 || length > MaxSettings || length > size-int64(footerSize) {
		return nil, 0, ErrDamaged
	}
	raw := make([]byte, length)
	start := size - int64(footerSize) - length
	if _, err := f.ReadAt(raw, start); err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(raw)
	if !bytes.Equal(sum[:], footer[:sha256.Size]) {
		return nil, 0, ErrDamaged
	}
	var s Settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, 0, ErrDamaged
	}
	if s.Version != 1 {
		return nil, 0, fmt.Errorf("the enrolment settings built into this program are version %d: this agent is too old for them", s.Version)
	}
	if s.Portal == "" || s.Token == "" || s.Pin == "" {
		return nil, 0, ErrDamaged
	}
	return &s, start, nil
}

// ProgramSize is the length of the program at path without built-in settings.
func ProgramSize(path string) (int64, error) {
	_, size, err := Read(path)
	return size, err
}

// CopyProgram copies the program at from to the writer, without built-in settings: the
// installed agent never keeps the enrolment token.
func CopyProgram(w io.Writer, from string) error {
	size, err := ProgramSize(from)
	if err != nil {
		return err
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.CopyN(w, in, size)
	return err
}

// Append returns program followed by the settings block (used by tests and the test portal;
// the portal does the same in PHP: Portal\AgentBundle).
func Append(program []byte, s Settings) ([]byte, error) {
	s.Version = 1
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxSettings {
		return nil, errors.New("settings too large")
	}
	sum := sha256.Sum256(raw)
	out := make([]byte, 0, len(program)+len(raw)+footerSize)
	out = append(out, program...)
	out = append(out, raw...)
	out = append(out, sum[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(raw)))
	return append(out, Magic...), nil
}

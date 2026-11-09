//go:build windows

package state

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiPrefix = "dpapi:"

var entropy = []byte("SohobOTP agent key v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func bytesOf(d *windows.DataBlob) []byte {
	out := make([]byte, d.Size)
	copy(out, unsafe.Slice(d.Data, d.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(d.Data)))
	return out
}

// sealKey encrypts a private key with DPAPI, machine scope: only this computer can open it,
// so a copied state file is useless elsewhere (the folder ACL keeps users out).
func sealKey(raw []byte) (string, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(blob(raw), nil, blob(entropy), 0, nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return "", err
	}
	return dpapiPrefix + b64.EncodeToString(bytesOf(&out)), nil
}

// openKey decrypts a DPAPI-sealed key; a plain base64 key (older state) is still accepted.
func openKey(s string) ([]byte, error) {
	if !strings.HasPrefix(s, dpapiPrefix) {
		return b64.DecodeString(s)
	}
	sealed, err := b64.DecodeString(strings.TrimPrefix(s, dpapiPrefix))
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return bytesOf(&out), nil
}

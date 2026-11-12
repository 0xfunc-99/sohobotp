package bundle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(p, data, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoundTripAndStrip(t *testing.T) {
	program := bytes.Repeat([]byte("PROGRAM-"), 5000)
	want := Settings{Portal: "https://otp.example.test", Token: "tok_abc", Pin: "AB12-CD34", CAPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}
	data, err := Append(program, want)
	if err != nil {
		t.Fatal(err)
	}
	p := write(t, data)
	got, size, err := Read(p)
	if err != nil || got == nil {
		t.Fatalf("settings not read: %v", err)
	}
	want.Version = 1
	if *got != want || size != int64(len(program)) {
		t.Fatalf("got %+v size %d", got, size)
	}
	var copy bytes.Buffer
	if err := CopyProgram(&copy, p); err != nil || !bytes.Equal(copy.Bytes(), program) {
		t.Fatalf("the installed copy must be the program without the settings (token): %v, %d bytes", err, copy.Len())
	}
	if bytes.Contains(copy.Bytes(), []byte("tok_abc")) {
		t.Fatal("token left in the installed copy")
	}
}

func TestPlainProgram(t *testing.T) {
	for _, data := range [][]byte{[]byte("short"), bytes.Repeat([]byte("x"), 4096)} {
		p := write(t, data)
		s, size, err := Read(p)
		if err != nil || s != nil || size != int64(len(data)) {
			t.Fatalf("plain program: %+v %d %v", s, size, err)
		}
	}
}

func TestDamagedRefused(t *testing.T) {
	program := bytes.Repeat([]byte("P"), 1000)
	good, _ := Append(program, Settings{Portal: "https://a", Token: "t", Pin: "p"})
	flip := append([]byte(nil), good...)
	flip[len(program)+5] ^= 1 // one bit of the settings
	short := append([]byte(nil), good...)
	short[len(short)-len(Magic)-1] = 0xff // length beyond the file
	noToken, _ := Append(program, Settings{Portal: "https://a", Pin: "p"})
	for name, data := range map[string][]byte{"changed settings": flip, "wrong length": short, "no token": noToken} {
		if s, _, err := Read(write(t, data)); s != nil || !errors.Is(err, ErrDamaged) {
			t.Fatalf("%s: must be refused, got %+v %v", name, s, err)
		}
	}
}

// The portal builds the settings block in PHP (Portal\AgentBundle::trailer); testdata holds
// its output for fixed values, checked on the PHP side by portal/tests/unit.php.
func TestPortalTrailer(t *testing.T) {
	trailer, err := os.ReadFile("testdata/portal-trailer.bin")
	if err != nil {
		t.Fatal(err)
	}
	program := bytes.Repeat([]byte{0x7f, 'E', 'L', 'F'}, 300)
	s, size, err := Read(write(t, append(append([]byte(nil), program...), trailer...)))
	if err != nil || s == nil {
		t.Fatalf("the portal's settings block is not read: %v", err)
	}
	if s.Portal != "https://otp.example.test:8443" || s.Token != "sohobenrol_0123456789abcdef" || len(s.Pin) != 64 ||
		!bytes.HasPrefix([]byte(s.CAPEM), []byte("-----BEGIN CERTIFICATE-----\n")) || size != int64(len(program)) {
		t.Fatalf("got %+v size %d", s, size)
	}
}

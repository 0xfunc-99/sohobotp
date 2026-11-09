package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type vectors struct {
	PortalSignSeed   string `json:"portal_sign_seed"`
	PortalSignPublic string `json:"portal_sign_public"`
	PortalKeyPin     string `json:"portal_key_pin"`
	AgentSignSeed    string `json:"agent_sign_seed"`
	AgentSignPublic  string `json:"agent_sign_public"`
	AgentBoxPublic   string `json:"agent_box_public"`
	AgentBoxSecret   string `json:"agent_box_secret"`
	Enroll           struct {
		Token, Message, Proof string
	} `json:"enroll"`
	Request struct {
		Method, URI, Time, Nonce, Body, Message, Signature string
	} `json:"request"`
	Config struct {
		Envelope          Envelope `json:"envelope"`
		PayloadJSON       string   `json:"payload_json"`
		RadiusSecretPlain string   `json:"radius_secret_plain"`
	} `json:"config"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "portal", "docs", "agent-protocol-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func dec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func boxKeys(t *testing.T, v vectors) (*[32]byte, *[32]byte) {
	var pub, priv [32]byte
	copy(priv[:], dec(t, v.AgentBoxSecret))
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], derived)
	if b64.EncodeToString(pub[:]) != v.AgentBoxPublic {
		t.Fatal("X25519 public key derived in Go differs from libsodium")
	}
	return &pub, &priv
}

func TestVectorsEnrolment(t *testing.T) {
	v := load(t)
	agent := ed25519.NewKeyFromSeed(dec(t, v.AgentSignSeed))
	if b64.EncodeToString(agent.Public().(ed25519.PublicKey)) != v.AgentSignPublic {
		t.Fatal("Ed25519 key from seed differs from libsodium")
	}
	boxPub, _ := boxKeys(t, v)
	msg := EnrollMessage(v.Enroll.Token, agent.Public().(ed25519.PublicKey), boxPub)
	if string(msg) != v.Enroll.Message {
		t.Fatalf("enrolment message differs:\n%q\n%q", msg, v.Enroll.Message)
	}
	if b64.EncodeToString(ed25519.Sign(agent, msg)) != v.Enroll.Proof {
		t.Fatal("enrolment proof differs from libsodium")
	}
}

func TestVectorsRequest(t *testing.T) {
	v := load(t)
	agent := ed25519.NewKeyFromSeed(dec(t, v.AgentSignSeed))
	r := v.Request
	msg := RequestMessage(r.Method, r.URI, r.Time, r.Nonce, []byte(r.Body))
	if string(msg) != r.Message {
		t.Fatalf("request message differs:\n%q\n%q", msg, r.Message)
	}
	if b64.EncodeToString(ed25519.Sign(agent, msg)) != r.Signature {
		t.Fatal("request signature differs from libsodium")
	}
}

func TestVectorsPin(t *testing.T) {
	v := load(t)
	if Pin(dec(t, v.PortalSignPublic)) != v.PortalKeyPin {
		t.Fatal("pin differs")
	}
	if NormalisePin(" 34750F98BD59FCFC 946da45aaabe933b e154a4b5094e1c4a bf42866505f3c97e ") != v.PortalKeyPin {
		t.Fatal("pin as shown on the enrolment page not accepted")
	}
}

func TestVectorsConfig(t *testing.T) {
	v := load(t)
	portal := ed25519.NewKeyFromSeed(dec(t, v.PortalSignSeed))
	if b64.EncodeToString(ed25519.Sign(portal, append([]byte(configPrefix), v.Config.PayloadJSON...))) != v.Config.Envelope.Signature {
		t.Fatal("config signature differs from libsodium")
	}
	boxPub, boxPriv := boxKeys(t, v)
	pub := portal.Public().(ed25519.PublicKey)
	cfg, err := OpenConfig(&v.Config.Envelope, pub, "e8f2c1a9b4d7e6f5a3c2", "linux", 0, boxPub, boxPriv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 4 || cfg.Secrets["radius_secret"] != v.Config.RadiusSecretPlain {
		t.Fatalf("unexpected config %+v", cfg)
	}
	var policy LinuxPolicy
	if err := json.Unmarshal(cfg.Policy, &policy); err != nil || !policy.Enabled || len(policy.RadiusServers) != 1 || policy.RadiusServers[0].Port != 1812 {
		t.Fatalf("policy %+v err %v", policy, err)
	}
}

func TestConfigRefusals(t *testing.T) {
	v := load(t)
	portal := ed25519.NewKeyFromSeed(dec(t, v.PortalSignSeed))
	pub := portal.Public().(ed25519.PublicKey)
	boxPub, boxPriv := boxKeys(t, v)
	env := v.Config.Envelope
	id := "e8f2c1a9b4d7e6f5a3c2"

	otherPortal, _, _ := ed25519.GenerateKey(rand.Reader)
	otherBoxPub, otherBoxPriv, _ := box.GenerateKey(rand.Reader)
	tampered := env
	tampered.Payload = b64.EncodeToString([]byte(string(dec(t, env.Payload)) + " "))

	cases := []struct {
		name string
		run  func() error
		want error
	}{
		{"wrong pinned key", func() error { _, e := OpenConfig(&env, otherPortal, id, "linux", 0, boxPub, boxPriv); return e }, ErrSignature},
		{"tampered payload", func() error { _, e := OpenConfig(&tampered, pub, id, "linux", 0, boxPub, boxPriv); return e }, ErrSignature},
		{"other endpoint", func() error {
			_, e := OpenConfig(&env, pub, "00000000000000000000", "linux", 0, boxPub, boxPriv)
			return e
		}, ErrEndpoint},
		{"other OS", func() error { _, e := OpenConfig(&env, pub, id, "windows", 0, boxPub, boxPriv); return e }, ErrOS},
		{"replay of applied version", func() error { _, e := OpenConfig(&env, pub, id, "linux", 4, boxPub, boxPriv); return e }, ErrRollback},
		{"rollback to older version", func() error { _, e := OpenConfig(&env, pub, id, "linux", 9, boxPub, boxPriv); return e }, ErrRollback},
		{"secret sealed to another key", func() error { _, e := OpenConfig(&env, pub, id, "linux", 0, otherBoxPub, otherBoxPriv); return e }, ErrSecret},
	}
	for _, c := range cases {
		if err := c.run(); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

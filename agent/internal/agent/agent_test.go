package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"multiotp-portal/agent/internal/client"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

var b64 = base64.StdEncoding

// fakePortal implements the portal side of the protocol for the loop tests.
type fakePortal struct {
	t        *testing.T
	key      ed25519.PrivateKey
	agentPub ed25519.PublicKey
	boxPub   *[32]byte
	mode     string // active | pending | disabled | forged
	version  int
	seen     protocol.CheckinRequest
}

func (f *fakePortal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	msg := protocol.RequestMessage(r.Method, r.URL.RequestURI(), r.Header.Get("X-Agent-Time"), r.Header.Get("X-Agent-Nonce"), body)
	sig, _ := b64.DecodeString(r.Header.Get("X-Agent-Signature"))
	if !ed25519.Verify(f.agentPub, msg, sig) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"bad_signature","message":"x"}`))
		return
	}
	json.Unmarshal(body, &f.seen)
	switch f.mode {
	case "disabled":
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"disabled","message":"This endpoint has been disabled in the portal."}`))
		return
	case "pending":
		w.Write([]byte(`{"checkin_interval":60,"state":"pending","config":null,"update":null}`))
		return
	}
	reply := protocol.CheckinReply{CheckinInterval: 45, State: "active"}
	if f.seen.Applied.Version < f.version {
		sealed, _ := box.SealAnonymous(nil, []byte("Radius-Secret-0123"), f.boxPub, rand.Reader)
		payload, _ := json.Marshal(map[string]any{
			"endpoint_id": "e0000000000000000001", "version": f.version, "issued_at": time.Now().Unix(), "os": runtime.GOOS,
			"policy": map[string]any{"enabled": true}, "secrets": map[string]string{"radius_secret": b64.EncodeToString(sealed)},
		})
		signer := f.key
		if f.mode == "forged" {
			_, signer, _ = ed25519.GenerateKey(rand.Reader)
		}
		reply.Config = &protocol.Envelope{Payload: b64.EncodeToString(payload), Signature: b64.EncodeToString(ed25519.Sign(signer, append([]byte("multiotp-config-v1\n"), payload...)))}
	}
	json.NewEncoder(w).Encode(reply)
}

type recordApplier struct {
	got []*protocol.Config
	err error
}

func (r *recordApplier) Apply(cfg *protocol.Config) (string, error) {
	r.got = append(r.got, cfg)
	return "ok", r.err
}

func setup(t *testing.T) (*Agent, *fakePortal, *recordApplier) {
	t.Setenv("SOHOBOTP_AGENT_DIR", t.TempDir())
	portalPub, portalKey, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := state.NewKeys()
	fp := &fakePortal{t: t, key: portalKey, agentPub: keys.Sign.Public().(ed25519.PublicKey), boxPub: keys.BoxPub, mode: "active", version: 1}
	srv := httptest.NewTLSServer(fp)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	st := &state.State{PortalURL: srv.URL, CAFile: ca, EndpointID: "e0000000000000000001", PortalKey: b64.EncodeToString(portalPub), Applied: protocol.Applied{Status: "none"}}
	if err := st.Store(keys); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(srv.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordApplier{}
	return &Agent{St: st, Keys: keys, Client: c, Applier: rec, Log: func(string, ...any) {}, now: time.Now}, fp, rec
}

func TestCheckinAppliesAndReports(t *testing.T) {
	a, fp, rec := setup(t)
	wait, err := a.Once()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 1 || rec.got[0].Secrets["radius_secret"] != "Radius-Secret-0123" || a.St.Applied.Version != 1 || a.St.Applied.Status != "applied" {
		t.Fatalf("config not applied: %+v %+v", rec.got, a.St.Applied)
	}
	if wait != 45*time.Second {
		t.Fatalf("interval %v", wait)
	}
	a.Once()
	if fp.seen.Applied.Version != 1 || fp.seen.Applied.Status != "applied" || len(rec.got) != 1 {
		t.Fatal("result not reported, or config applied twice")
	}
	saved, _ := state.Load()
	if saved.Applied.Version != 1 {
		t.Fatal("state not saved")
	}
}

func TestFailedApplyIsReportedAndRetriedLater(t *testing.T) {
	a, fp, rec := setup(t)
	clock := time.Now()
	a.now = func() time.Time { return clock }
	rec.err = errors.New("SohobOTP Sign-in is not installed")
	a.Once()
	if a.St.Applied.Status != "failed" || a.St.Applied.Error == "" || a.St.RetryConfig == nil {
		t.Fatalf("%+v", a.St.Applied)
	}
	a.Once() // too early: reported, not retried
	if fp.seen.Applied.Status != "failed" || len(rec.got) != 1 {
		t.Fatal("failure not reported, or retried too early")
	}
	clock = clock.Add(61 * time.Second)
	a.Once() // retry, fails again: next delay doubles
	if len(rec.got) != 2 || a.St.Applied.Status != "failed" || a.St.RetryAt != clock.Unix()+120 {
		t.Fatalf("retry: %d applies, %+v, retry at %d", len(rec.got), a.St.Applied, a.St.RetryAt-clock.Unix())
	}
	saved, _ := state.Load()
	if saved.RetryConfig == nil {
		t.Fatal("retry not saved (lost on restart)")
	}
	rec.err = nil
	clock = clock.Add(121 * time.Second)
	a.Once()
	if len(rec.got) != 3 || a.St.Applied.Status != "applied" || a.St.Applied.Version != 1 || a.St.RetryConfig != nil {
		t.Fatalf("retry did not apply: %+v", a.St.Applied)
	}
	if rec.got[2].Secrets["radius_secret"] != "Radius-Secret-0123" {
		t.Fatal("secret not opened on retry")
	}
	a.Once()
	if fp.seen.Applied.Status != "applied" || len(rec.got) != 3 {
		t.Fatal("success not reported, or applied again")
	}
}

func TestNewerConfigReplacesFailedOne(t *testing.T) {
	a, fp, rec := setup(t)
	rec.err = errors.New("apt locked")
	a.Once()
	rec.err = nil
	fp.version = 2
	a.Once()
	if a.St.Applied.Version != 2 || a.St.Applied.Status != "applied" || a.St.RetryConfig != nil || len(rec.got) != 2 {
		t.Fatalf("%+v", a.St.Applied)
	}
}

func TestTamperedRetryIsDropped(t *testing.T) {
	a, _, rec := setup(t)
	clock := time.Now()
	a.now = func() time.Time { return clock }
	rec.err = errors.New("x")
	a.Once()
	a.St.RetryConfig.Signature = a.St.RetryConfig.Signature[:10] + "AAAA" + a.St.RetryConfig.Signature[14:]
	clock = clock.Add(time.Hour)
	a.Once()
	if len(rec.got) != 1 || a.St.RetryConfig != nil {
		t.Fatal("a changed stored configuration was applied")
	}
}

func TestForgedConfigNeverApplied(t *testing.T) {
	a, fp, rec := setup(t)
	fp.mode = "forged"
	if _, err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 0 || a.St.Applied.Version != 0 || a.St.LastError == "" {
		t.Fatalf("forged config applied or not reported: %+v %q", a.St.Applied, a.St.LastError)
	}
}

func TestDisabledAndPendingKeepLastConfig(t *testing.T) {
	a, fp, rec := setup(t)
	a.Once()
	fp.mode = "disabled"
	wait, err := a.Once()
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || a.St.PortalState != "disabled" || a.St.Applied.Version != 1 {
		t.Fatalf("disabled: %v %+v", err, a.St)
	}
	if wait != 30*time.Second {
		t.Fatalf("first backoff %v", wait)
	}
	if w, _ := a.Once(); w != time.Minute {
		t.Fatalf("backoff must double, got %v", w)
	}
	fp.mode = "pending"
	if _, err := a.Once(); err != nil || a.St.PortalState != "pending" || len(rec.got) != 1 {
		t.Fatalf("pending: %v %+v", err, a.St)
	}
}

func TestPlainHTTPRefused(t *testing.T) {
	if _, err := client.New("http://portal.example.test", ""); err == nil {
		t.Fatal("http:// accepted")
	}
	_ = strconv.Itoa
}

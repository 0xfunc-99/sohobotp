// fakeportal is a minimal SohobOTP portal for testing the agent on a machine without the real
// portal (the Windows end-to-end test). It speaks the agent protocol exactly (enrolment proof,
// signed requests, signed configuration with sealed secrets) over HTTPS with its own test CA.
//
//	fakeportal --dir C:\sohobotp-test --addr 127.0.0.1:8443
//
// It writes into --dir: ca.pem, token.txt, pin.txt, expected.json (the values the agent must
// write) and state.json (the last check-in: endpoint id, applied version and status).
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"multiotp-portal/agent/internal/protocol"
)

var b64 = base64.StdEncoding

type endpoint struct {
	sign ed25519.PublicKey
	box  *[32]byte
	os   string
}

type portal struct {
	dir       string
	addr      string
	key       ed25519.PrivateKey
	token     string
	cpSecret  string
	radiusSec string
	mu        sync.Mutex
	endpoints map[string]*endpoint
	nonces    map[string]bool
}

func main() {
	dir := flag.String("dir", ".", "output folder")
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	p := &portal{dir: *dir, addr: *addr, key: key, endpoints: map[string]*endpoint{}, nonces: map[string]bool{},
		token: randHex(6) + "." + randB64url(24), cpSecret: randHex(24), radiusSec: "Radius-" + randHex(10)}
	cert, caPEM := makeCerts()
	write(p.dir, "ca.pem", caPEM)
	write(p.dir, "token.txt", []byte(p.token))
	write(p.dir, "pin.txt", []byte(protocol.Pin(key.Public().(ed25519.PublicKey))))
	srv := &http.Server{Addr: *addr, Handler: http.HandlerFunc(p.serve), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	log.Printf("fake portal on https://%s (folder %s)", *addr, *dir)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func (p *portal) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	switch r.URL.Query().Get("a") {
	case "enroll":
		p.enroll(w, body)
	case "checkin":
		p.checkin(w, r, body)
	default:
		fail(w, 404, "bad_request")
	}
}

func (p *portal) enroll(w http.ResponseWriter, body []byte) {
	var req protocol.EnrollRequest
	if json.Unmarshal(body, &req) != nil || req.Token != p.token {
		fail(w, 401, "bad_token")
		return
	}
	sign, _ := b64.DecodeString(req.SignKey)
	boxRaw, _ := b64.DecodeString(req.BoxKey)
	proof, _ := b64.DecodeString(req.Proof)
	if len(sign) != 32 || len(boxRaw) != 32 {
		fail(w, 400, "bad_request")
		return
	}
	boxKey := new([32]byte)
	copy(boxKey[:], boxRaw)
	if !ed25519.Verify(sign, protocol.EnrollMessage(req.Token, sign, boxKey), proof) {
		fail(w, 400, "bad_request")
		return
	}
	id := randHex(10)
	p.mu.Lock()
	p.endpoints[id] = &endpoint{sign: sign, box: boxKey, os: req.Inventory.OS}
	p.mu.Unlock()
	expected := map[string]any{
		"endpoint_id":          id,
		"multiOTPServers":      "https://" + p.addr + "/portal/cp.php?e=" + id,
		"multiOTPSharedSecret": p.cpSecret,
		"cpus_logon":           "0e", "cpus_unlock": "0d", "cpus_credui": "3e",
		"excluded_account": `.\breakglass`,
		"login_text":       "SohobOTP", "otp_text": "SohobOTP code",
	}
	raw, _ := json.MarshalIndent(expected, "", "  ")
	write(p.dir, "expected.json", raw)
	log.Printf("enrolled %s (%s)", id, req.Inventory.Hostname)
	reply(w, protocol.EnrollReply{EndpointID: id, PortalKey: b64.EncodeToString(p.key.Public().(ed25519.PublicKey)), CheckinInterval: 30})
}

func (p *portal) checkin(w http.ResponseWriter, r *http.Request, body []byte) {
	id := r.Header.Get("X-Agent-Id")
	p.mu.Lock()
	ep := p.endpoints[id]
	nonce := r.Header.Get("X-Agent-Nonce")
	seen := p.nonces[nonce]
	p.nonces[nonce] = true
	p.mu.Unlock()
	sig, _ := b64.DecodeString(r.Header.Get("X-Agent-Signature"))
	ts, _ := strconv.ParseInt(r.Header.Get("X-Agent-Time"), 10, 64)
	if ep == nil || seen || time.Since(time.Unix(ts, 0)).Abs() > 5*time.Minute ||
		!ed25519.Verify(ep.sign, protocol.RequestMessage(r.Method, r.URL.RequestURI(), r.Header.Get("X-Agent-Time"), nonce, body), sig) {
		fail(w, 401, "bad_signature")
		return
	}
	var req protocol.CheckinRequest
	_ = json.Unmarshal(body, &req)
	state, _ := json.MarshalIndent(map[string]any{"endpoint_id": id, "applied": req.Applied, "inventory": req.Inventory, "at": time.Now().Unix()}, "", "  ")
	write(p.dir, "state.json", state)
	out := protocol.CheckinReply{CheckinInterval: 30, State: "active"}
	if req.Applied.Version < 1 {
		out.Config = p.config(id, ep)
	}
	reply(w, out)
}

func (p *portal) config(id string, ep *endpoint) *protocol.Envelope {
	seal := func(s string) string {
		sealed, _ := box.SealAnonymous(nil, []byte(s), ep.box, rand.Reader)
		return b64.EncodeToString(sealed)
	}
	var policy any
	secrets := map[string]string{}
	if ep.os == "windows" {
		policy = protocol.WindowsPolicy{
			ServerURL: "https://" + p.addr + "/portal/cp.php?e=" + id, ServerTimeout: 5,
			CpusLogon: "0e", CpusUnlock: "0d", CpusCredui: "3e", ExcludedAccount: `.\breakglass`,
			CacheEnabled: true, TimeoutUnlock: 10, LoginText: "SohobOTP", OTPText: "SohobOTP code",
		}
		secrets["cp_shared_secret"] = seal(p.cpSecret)
	} else {
		policy = protocol.LinuxPolicy{Enabled: false}
	}
	policyRaw, _ := json.Marshal(policy)
	payload, _ := json.Marshal(map[string]any{"endpoint_id": id, "version": 1, "issued_at": time.Now().Unix(), "os": ep.os, "policy": json.RawMessage(policyRaw), "secrets": secrets})
	return &protocol.Envelope{Payload: b64.EncodeToString(payload), Signature: b64.EncodeToString(ed25519.Sign(p.key, append([]byte("multiotp-config-v1\n"), payload...)))}
}

// makeCerts creates a test CA and a server certificate for 127.0.0.1 and localhost.
func makeCerts() (tls.Certificate, []byte) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SohobOTP fake portal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	return tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"message":"fake portal"}`, code)
}

func write(dir, name string, data []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		log.Fatal(err)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randB64url(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

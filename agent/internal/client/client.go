// Package client talks to the portal agent API over HTTPS (portal/agent.php).
// Certificate verification is always on: --ca-file only adds a trusted CA.
package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

// APIError is an error answer from the portal ({"error": code, "message": text}).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("portal refused the request (%d %s): %s", e.Status, e.Code, e.Message)
}

// Client is bound to one portal.
type Client struct {
	base *url.URL
	http *http.Client
	now  func() time.Time
}

// New validates the portal URL (https only) and prepares TLS.
func New(portal, caFile string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(portal), "/"))
	if err != nil || u.Host == "" {
		return nil, errors.New("the portal address must look like https://portal.example.com")
	}
	if u.Scheme != "https" && os.Getenv("SOHOBOTP_AGENT_ALLOW_HTTP") != "1" {
		return nil, errors.New("the portal address must use https://")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("the CA file contains no PEM certificate")
		}
		cfg.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 30 * time.Second}
	return &Client{base: u, http: &http.Client{Transport: transport, Timeout: 60 * time.Second}, now: time.Now}, nil
}

// Host is the portal host name (used as the default RADIUS server by the portal).
func (c *Client) Host() string { return c.base.Hostname() }

func (c *Client) endpoint(action string) *url.URL {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/portal/agent.php"
	u.RawQuery = "a=" + action
	return &u
}

// Enroll registers the machine with an enrolment token.
func (c *Client) Enroll(token string, keys *state.Keys, inv protocol.Inventory) (*protocol.EnrollReply, error) {
	pub := keys.Sign.Public().(ed25519.PublicKey)
	req := protocol.EnrollRequest{
		Token:     token,
		SignKey:   base64.StdEncoding.EncodeToString(pub),
		BoxKey:    base64.StdEncoding.EncodeToString(keys.BoxPub[:]),
		Proof:     base64.StdEncoding.EncodeToString(ed25519.Sign(keys.Sign, protocol.EnrollMessage(token, pub, keys.BoxPub))),
		Inventory: inv,
	}
	var reply protocol.EnrollReply
	if err := c.post("enroll", req, nil, "", &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

// Checkin sends a signed check-in.
func (c *Client) Checkin(endpointID string, sign ed25519.PrivateKey, body protocol.CheckinRequest) (*protocol.CheckinReply, error) {
	var reply protocol.CheckinReply
	if err := c.post("checkin", body, sign, endpointID, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *Client) post(action string, payload any, sign ed25519.PrivateKey, endpointID string, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	u := c.endpoint(action)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sohobotp-agent")
	if sign != nil {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ts := strconv.FormatInt(c.now().Unix(), 10)
		n := base64.StdEncoding.EncodeToString(nonce)
		msg := protocol.RequestMessage(http.MethodPost, u.RequestURI(), ts, n, body)
		req.Header.Set("X-Agent-Id", endpointID)
		req.Header.Set("X-Agent-Time", ts)
		req.Header.Set("X-Agent-Nonce", n)
		req.Header.Set("X-Agent-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(sign, msg)))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the portal: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{Status: resp.StatusCode, Code: "http_error", Message: http.StatusText(resp.StatusCode)}
		var body struct{ Error, Message string }
		if json.Unmarshal(raw, &body) == nil && body.Error != "" {
			apiErr.Code, apiErr.Message = body.Error, body.Message
		}
		return apiErr
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unexpected answer from the portal: %w", err)
	}
	return nil
}

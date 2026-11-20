package agent

import (
	"errors"
	"strings"
	"testing"

	"multiotp-portal/agent/internal/protocol"
)

func TestLostOrderCarriedOutOnce(t *testing.T) {
	a, fp, _ := setup(t)
	erased, signedOut := 0, 0
	eraseOfflineCopy = func() (int, error) { erased++; return 3, nil }
	signOutEveryone = func() (int, error) { signedOut++; return 2, nil }
	t.Cleanup(func() { eraseOfflineCopy, signOutEveryone = eraseSigninCache, signOutSessions })

	fp.policy = map[string]any{"enabled": true, "lost": map[string]any{"id": "0123456789abcdef", "sign_out": true}}
	if _, err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if erased != 1 || signedOut != 1 || a.St.LostDone != "0123456789abcdef" {
		t.Fatalf("order not carried out: erased %d, signed out %d, state %q", erased, signedOut, a.St.LostDone)
	}
	if len(a.St.Events) != 1 || a.St.Events[0].Kind != protocol.EventLostDone ||
		a.St.Events[0].Detail != "order 0123456789abcdef: offline copy erased (3 files), 2 sessions signed out" {
		t.Fatalf("event: %+v", a.St.Events)
	}
	// the same order in a later configuration (another change of the policy): not again
	fp.version = 2
	if _, err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if erased != 1 || signedOut != 1 || len(fp.events) != 1 || fp.events[0].Kind != protocol.EventLostDone {
		t.Fatalf("carried out twice or not reported: erased %d, signed out %d, portal got %+v", erased, signedOut, fp.events)
	}
	// found
	fp.version, fp.policy = 3, map[string]any{"enabled": true}
	a.Once()
	if a.St.LostDone != "" {
		t.Fatal("found: the order is still remembered")
	}
	// a new order, without sign-out, whose erasing fails: reported, not retried forever
	eraseOfflineCopy = func() (int, error) { erased++; return 0, errors.New("access denied") }
	fp.version, fp.policy = 4, map[string]any{"enabled": true, "lost": map[string]any{"id": "fedcba9876543210", "sign_out": false}}
	a.Once()
	if erased != 2 || signedOut != 1 || a.St.LostDone != "fedcba9876543210" ||
		!strings.Contains(a.St.Events[len(a.St.Events)-1].Detail, "offline copy NOT erased: access denied") {
		t.Fatalf("second order: erased %d, signed out %d, events %+v", erased, signedOut, a.St.Events)
	}
}

func TestLostOrderAlsoWhenApplyFails(t *testing.T) {
	a, fp, rec := setup(t)
	erased := 0
	eraseOfflineCopy = func() (int, error) { erased++; return 0, nil }
	signOutEveryone = func() (int, error) { t.Fatal("sign-out not asked"); return 0, nil }
	t.Cleanup(func() { eraseOfflineCopy, signOutEveryone = eraseSigninCache, signOutSessions })
	rec.err = errors.New("apt locked")
	fp.policy = map[string]any{"enabled": true, "lost": map[string]any{"id": "0123456789abcdef", "sign_out": false}}
	a.Once()
	if erased != 1 || a.St.Applied.Status != "failed" || a.St.Events[0].Detail != "order 0123456789abcdef" {
		t.Fatalf("erased %d, applied %+v, events %+v", erased, a.St.Applied, a.St.Events)
	}
}

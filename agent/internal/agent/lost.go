package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"multiotp-portal/agent/internal/protocol"
)

// Lost or stolen (portal: the computer's page). The portal already refuses every sign-in on
// the computer; the agent removes what still works without the portal:
//   - Windows: SohobOTP Sign-in's offline copy of the users' code data (with it, the right
//     code signs in while the computer is offline); the configuration turns the copy off so
//     no new one is made;
//   - with SignOut: everyone signed in now is signed out, so they must sign in again (and
//     are refused).
//
// Each order (its id) is carried out once; the portal is told (event lost_done).
var (
	eraseOfflineCopy = eraseSigninCache // (files erased, error)
	signOutEveryone  = signOutSessions  // (sessions signed out, error)
)

func (a *Agent) obeyLost(cfg *protocol.Config) {
	var p struct {
		Lost *protocol.LostOrder `json:"lost"`
	}
	if err := json.Unmarshal(cfg.Policy, &p); err != nil || p.Lost == nil || p.Lost.ID == "" {
		if a.St.LostDone != "" {
			a.Log("lost or stolen: the portal marked this computer as found")
			a.St.LostDone = ""
		}
		return
	}
	if p.Lost.ID == a.St.LostDone {
		return
	}
	a.Log("LOST OR STOLEN: this computer was reported lost or stolen in the portal: sign-ins are refused")
	var done []string
	n, err := eraseOfflineCopy()
	switch {
	case err != nil:
		done = append(done, "offline copy NOT erased: "+err.Error())
	case n > 0:
		done = append(done, fmt.Sprintf("offline copy erased (%d files)", n))
	}
	if p.Lost.SignOut {
		n, err := signOutEveryone()
		if err != nil {
			done = append(done, "sign-out failed: "+err.Error())
		} else {
			done = append(done, fmt.Sprintf("%d sessions signed out", n))
		}
	}
	detail := "order " + p.Lost.ID
	if len(done) > 0 {
		detail += ": " + strings.Join(done, ", ")
	}
	a.Log("lost or stolen: %s", detail)
	addEvent(a.St, a.now().Unix(), protocol.EventLostDone, detail)
	a.St.LostDone = p.Lost.ID
}

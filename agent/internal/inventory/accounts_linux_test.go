//go:build linux

package inventory

import "testing"

func TestParseAccounts(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/sh
svc:x:1002:1002::/srv:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
bad;name:x:1003:1003::/home/x:/bin/bash
locked:x:1004:1004::/home/locked:/bin/false
`
	group := "sudo:x:27:alice\nusers:x:100:deploy\n"
	got := parseAccounts(passwd, group, 1000)
	want := []string{"alice", "deploy", "root"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, a := range got {
		if a.Name != want[i] || a.Kind != "local" {
			t.Fatalf("got %+v", got)
		}
	}
	if !got[0].Admin || got[1].Admin || !got[2].Admin {
		t.Fatalf("admin flags wrong: %+v", got)
	}
	if uidMin("UID_MIN\t\t\t 500\n") != 500 || uidMin("") != 1000 {
		t.Fatal("UID_MIN")
	}
}

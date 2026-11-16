package tamper

import "testing"

func TestHashVector(t *testing.T) {
	// the same vector is checked by the portal (portal/tests/unit.php)
	const want = "c16b05e4423b985807e9a2cf3087d72744ec3a097f991753d6e63ad3d28ecdba"
	if got := Hash("e0000000000000000001", "ABCD-EFGH-JKLM"); got != want {
		t.Fatalf("hash %s", got)
	}
}

func TestCheck(t *testing.T) {
	h := Hash("e0000000000000000001", "ABCD-EFGH-JKLM")
	for _, code := range []string{"ABCD-EFGH-JKLM", "abcdefghjklm", " abcd efgh jklm "} {
		if !Check(h, "e0000000000000000001", code) {
			t.Errorf("%q refused", code)
		}
	}
	for _, code := range []string{"", "ABCD-EFGH-JKLN", "ABCD"} {
		if Check(h, "e0000000000000000001", code) {
			t.Errorf("%q accepted", code)
		}
	}
	if Check(h, "e0000000000000000002", "ABCD-EFGH-JKLM") {
		t.Error("the code of another endpoint was accepted")
	}
	if Check("", "e0000000000000000001", "") || Check("zz", "e0000000000000000001", "ABCD") {
		t.Error("an empty or malformed hash matched")
	}
}

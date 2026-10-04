package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

func fixture() (*GS, *LEO, *LEO, *HAP, *EU, *InitialSession) {
	gs := NewGS()
	l1 := RegisterLEO(gs, "L1")
	l2 := RegisterLEO(gs, "L2")
	l2.SSK = clone(l1.SSK)
	h := RegisterHAP(gs, "H")
	u := RegisterEU(gs, "U", "PW")
	s, ok := InitialAuthentication(u, h, l1)
	if !ok {
		panic("initial auth")
	}
	return gs, l1, l2, h, u, s
}

func TestPaperProfile(t *testing.T) {
	initCurve()
	gs, l1, l2, _, u, s := fixture()
	if !bytes.Equal(s.SK, u.SK) || !bytes.Equal(s.TK, u.TK) {
		t.Fatal("key mismatch")
	}
	if _, ok := PreHandover(l1, l2, u, s); !ok {
		t.Fatal("pre")
	}
	if _, ok := HandoverAuthentication(u, l2); !ok {
		t.Fatal("handover")
	}
	r := RevokeUser(gs, l2, u)
	if !bytes.Equal(r.ID, u.ID) {
		t.Fatal("RID open")
	}
	l2.SSK = randomBytes(32)
	if _, ok := PreHandover(l1, l2, u, s); ok {
		t.Fatal("wrong target key")
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Add(-time.Hour).UnixNano()))
	if fresh(ts[:]) {
		t.Fatal("stale")
	}
	t.Logf("actual point bytes=%d, fuzzy verifier=%d, AES key bits=128", len(u.Public), u.NEU)
}

func TestPerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	initCurve()
	gs, l1, l2, h, u, s := fixture()
	measureStage(t, "setup_GS", func() func() { return func() { NewGS() } })
	measureStage(t, "register_LEO", func() func() { return func() { RegisterLEO(gs, "L") } })
	measureStage(t, "register_HAP", func() func() { return func() { RegisterHAP(gs, "H") } })
	measureStage(t, "register_EU", func() func() { return func() { RegisterEU(gs, "U", "PW") } })
	measureStage(t, "initial_auth_all_roles", func() func() {
		return func() {
			var ok bool
			s, ok = InitialAuthentication(u, h, l1)
			if !ok {
				t.Fatal("auth")
			}
		}
	})
	measureStage(t, "pre_handover_all_roles", func() func() {
		return func() {
			if _, ok := PreHandover(l1, l2, u, s); !ok {
				t.Fatal("pre")
			}
		}
	})
	measureStage(t, "handover_all_roles", func() func() {
		u.SK = clone(s.SK)
		u.TK = clone(s.TK)
		u.TID2 = clone(s.TID2)
		if _, ok := PreHandover(l1, l2, u, s); !ok {
			t.Fatal("pre")
		}
		return func() {
			if _, ok := HandoverAuthentication(u, l2); !ok {
				t.Fatal("handover")
			}
		}
	})
	measureStage(t, "open_and_revoke_registry", func() func() { return func() { RevokeUser(gs, l2, u) } })
	measureStage(t, "timer_floor", func() func() { return func() {} })
}

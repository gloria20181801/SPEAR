package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func roleInitial20(clock *roleClock, eu *EU, hap *HAP, leo *LEO) (*InitialSession, bool) {
	hpw := hash(eu.Password, eu.RE)
	hid := xorBytes(eu.SHID, hash(hpw, eu.RE))
	mi := xorBytes(eu.SMi, hash(eu.ID, hid, eu.RE, eu.Password))
	pid := xorBytes(eu.SPID, hash(eu.RE, mi, hpw))
	si := hash(pid, mi)
	vi := fuzzy(hash(pid, si, hid, hpw, mi), eu.NEU)
	if !bytes.Equal(vi, eu.Vi) {
		return nil, false
	}

	rm1 := randomBytes(32)
	tm1 := timestampBytes()
	ehi := scalarMult(hap.Public, si)
	pki := baseMult(rm1)
	ai := scalarMult(hap.Public, rm1)
	tid1 := xorBytes(pid, hash(ai, hap.PID, tm1))
	vm1 := hash(ehi, tm1, hap.PID, pid)

	clock.next("HAP")
	hapSecret := hash(hap.K, hap.M)
	if !fresh(tm1) {
		return nil, false
	}
	ak := scalarMult(pki, hapSecret)
	pidFromTID := xorBytes(tid1, hash(ak, hap.PID, tm1))
	ehk := scalarMult(eu.Public, hapSecret)
	if !bytes.Equal(vm1, hash(ehk, tm1, hap.PID, pidFromTID)) {
		return nil, false
	}

	tm2 := timestampBytes()
	hlk := scalarMult(leo.Public, hapSecret)
	htid1 := xorBytes(pidFromTID, hash(hlk, tm2))
	vm2 := hash(hap.PID, pidFromTID, tm2)

	clock.next("LEO")
	if !fresh(tm2) {
		return nil, false
	}
	leoSecret := hash(leo.K, leo.M)
	hlj := scalarMult(hap.Public, leoSecret)
	pidAtLEO := xorBytes(htid1, hash(hlj, tm2))
	if !bytes.Equal(vm2, hash(hap.PID, pidAtLEO, tm2)) {
		return nil, false
	}

	rm2 := randomBytes(32)
	tm3 := timestampBytes()
	pkj := baseMult(rm2)
	lij := scalarMult(pki, rm2)
	tk := hash(lij, pidAtLEO, leo.PID)
	sk := hash(lij, leo.PID, tk, tm3)
	vm3 := hash(sk, tk, lij, tm3)

	clock.next("HAP")
	if !fresh(tm3) {
		return nil, false
	}
	spm := xorBytes(leo.PID, hash(ehk, tm3, ak))
	vm4 := hash(vm3, leo.PID)

	clock.next("UE")
	if !fresh(tm3) {
		return nil, false
	}
	lijEU := scalarMult(pkj, rm1)
	pidLEO := xorBytes(spm, hash(ehi, tm3, ai))
	tkEU := hash(lijEU, pid, pidLEO)
	tid2 := hash(pid, tkEU)
	skEU := hash(lijEU, pidLEO, tkEU, tm3)
	vm4Expected := hash(hash(skEU, tkEU, lijEU, tm3), pidLEO)
	if !bytes.Equal(vm4, vm4Expected) {
		return nil, false
	}

	eu.TK = tkEU
	eu.TID2 = tid2
	eu.SK = skEU
	eu.TargetID = leo.PID
	return &InitialSession{PIDi: pid, PIDLEO: leo.PID, TK: tk, TID2: tid2, SK: sk, RM1: rm1, PKi: pki}, true
}

func rolePre20(clock *roleClock, source *LEO, target *LEO, eu *EU, s *InitialSession) (*PreHandoverBundle, bool) {
	rs1 := randomBytes(32)
	ts1 := timestampBytes()
	er := hash(target.PID, rs1)
	tid2 := hash(s.PIDi, s.TK)
	vs1 := hash(er, rs1, target.PID, tid2, ts1)
	vs2 := hash(er, target.PID, ts1)

	msgLEOPlain := concat(s.PIDi, rs1, s.TK, vs1)
	msgEUPlain := concat(er, target.PID, vs2)
	toLEO2 := seal(source.SSK, msgLEOPlain, ts1)
	toEU := seal(s.SK, msgEUPlain, ts1)

	clock.next("target_LEO")
	if !fresh(ts1) {
		return nil, false
	}
	leoPlain, ok := open(target.SSK, toLEO2, ts1)
	if !ok || len(leoPlain) != 128 {
		return nil, false
	}
	pid := clone(leoPlain[0:32])
	rs := clone(leoPlain[32:64])
	tk := clone(leoPlain[64:96])
	recvVS1 := clone(leoPlain[96:128])
	er2 := hash(target.PID, rs)
	tid := hash(pid, tk)
	if !bytes.Equal(recvVS1, hash(er2, rs, target.PID, tid, ts1)) {
		return nil, false
	}
	target.Handover[string(tid)] = LEOHandoverState{
		RS1:    rs,
		PIDi:   pid,
		TK:     tk,
		TID2:   tid,
		ER:     er2,
		PIDLEO: target.PID,
	}

	clock.next("UE")
	if !fresh(ts1) {
		return nil, false
	}
	euPlain, ok := open(eu.SK, toEU, ts1)
	if !ok || len(euPlain) != 96 {
		return nil, false
	}
	euER := clone(euPlain[0:32])
	euPIDLEO2 := clone(euPlain[32:64])
	euVS2 := clone(euPlain[64:96])
	if !bytes.Equal(euVS2, hash(euER, euPIDLEO2, ts1)) {
		return nil, false
	}
	eu.ER = euER
	eu.TargetID = euPIDLEO2
	eu.TID2 = tid
	return &PreHandoverBundle{ToLEO2: toLEO2, ToEU: toEU, TS1: ts1}, true
}

func roleHand20(clock *roleClock, eu *EU, leo *LEO) ([]byte, bool) {
	state, ok := leo.Handover[string(eu.TID2)]
	if !ok {
		return nil, false
	}

	ta1 := timestampBytes()
	er := hash(leo.PID, state.RS1)
	tid2 := hash(state.PIDi, state.TK)
	ra1 := xorBytes(state.RS1, hash(er, state.TK, ta1))
	va1 := hash(state.RS1, tid2, state.TK, leo.PID, er, ta1)
	state.TA1 = ta1
	leo.Handover[string(tid2)] = state

	clock.next("UE")
	if !fresh(ta1) || !fresh(ta1) {
		return nil, false
	}
	rs1 := xorBytes(ra1, hash(eu.ER, eu.TK, ta1))
	erPrime := hash(eu.TargetID, rs1)
	va1Expected := hash(rs1, eu.TID2, eu.TK, eu.TargetID, erPrime, ta1)
	if !bytes.Equal(va1, va1Expected) || !bytes.Equal(eu.ER, erPrime) {
		return nil, false
	}

	ra := randomBytes(32)
	ta2 := timestampBytes()
	ra2 := xorBytes(ra, hash(eu.TK, ta1, eu.PID, eu.ER))
	skNew := hash(rs1, ra, ta2, eu.TK, eu.TargetID)
	tkNew := hash(eu.TK, ra, eu.PID, eu.TargetID)
	tid3 := hash(eu.PID, tkNew)
	va2 := hash(ra, skNew, tid3, tkNew, ta2)

	clock.next("target_LEO")
	if !fresh(ta2) || !fresh(ta2) {
		return nil, false
	}
	raAtLEO := xorBytes(ra2, hash(state.TK, ta1, state.PIDi, state.ER))
	skAtLEO := hash(state.RS1, raAtLEO, ta2, state.TK, leo.PID)
	tkAtLEO := hash(state.TK, raAtLEO, state.PIDi, leo.PID)
	tid3AtLEO := hash(state.PIDi, tkAtLEO)
	va2Expected := hash(raAtLEO, skAtLEO, tid3AtLEO, tkAtLEO, ta2)
	if !bytes.Equal(va2, va2Expected) {
		return nil, false
	}

	eu.SK = skNew
	eu.TK = tkNew
	eu.TID2 = tid3
	delete(leo.Handover, string(tid2))
	leo.Handover[string(tid3)] = LEOHandoverState{
		RS1:    state.RS1,
		PIDi:   state.PIDi,
		TK:     tkAtLEO,
		TID2:   tid3AtLEO,
		ER:     state.ER,
		PIDLEO: leo.PID,
	}
	return skNew, true
}

func TestRolePerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	initCurve()
	_, l1, l2, h, u, s := fixture()
	measureRoles(t, "access", func() func() map[string]int64 {
		return func() map[string]int64 {
			c := newRoleClock("UE")
			_, ok := roleInitial20(c, u, h, l1)
			if !ok {
				t.Fatal("initial")
			}
			return c.done()
		}
	})
	measureRoles(t, "handover_pre", func() func() map[string]int64 {
		return func() map[string]int64 {
			u.SK = clone(s.SK)
			u.TK = clone(s.TK)
			c := newRoleClock("source_LEO")
			_, ok := rolePre20(c, l1, l2, u, s)
			if !ok {
				t.Fatal("pre")
			}
			return c.done()
		}
	})
	measureRoles(t, "handover", func() func() map[string]int64 {
		u.SK = clone(s.SK)
		u.TK = clone(s.TK)
		u.TID2 = clone(s.TID2)
		if _, ok := PreHandover(l1, l2, u, s); !ok {
			t.Fatal("pre")
		}
		return func() map[string]int64 {
			c := newRoleClock("target_LEO")
			_, ok := roleHand20(c, u, l2)
			if !ok {
				t.Fatal("hand")
			}
			return c.done()
		}
	})
	fmt.Printf("WIRE20 MEC point=%d initial=%d pre=%d hand_logical=%d hand_relay=%d\n", len(u.Public), initialAuthCommBytes(), preHandoverCommBytes(), handoverLogicalCommBytes(), handoverRelayedCommBytes())
}

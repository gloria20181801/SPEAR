package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestRolePerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	p, u, k, cred, attrs := pktFixture(3)
	leo := LEOSetup(p)
	next := LEOSetup(p)
	gs := refGS(p, "GS1", 1, true)
	g2 := refGS(p, "GS2", 1, false)
	session := refAccess(p, u, k, cred, attrs, leo, gs)
	measureRoles(t, "access", func() func() map[string]int64 {
		return func() map[string]int64 {
			c := newRoleClock("UE")
			var ru Fr
			ru.Random()
			Ru := rgMul(p.G0, ru)
			msg := Ru.Serialize()
			tok, tin, _ := RefShowWithMessage(p, u, k, cred, attrs, attrs[:2], &Dispenser{Remaining: []uint64{1}}, msg)
			c.next("LEO")
			if !RefVerifyWithMessage(p, k, tok, tin, attrs[:2], nil, msg) {
				t.Fatal("proof")
			}
			klu := deriveLinkKeyFromPK(&Ru, &leo.Sk)
			klg := deriveLinkKeyFromPK(&gs.gs.Pk, &leo.Sk)
			up := refGSPayload(gs)
			gp := append(append(Ru.Serialize(), uint64Bytes(cred.TP)...), uint64Bytes(tok.Ju)...)
			cu, cg := refSeal(klu, up), refSeal(klg, gp)
			c.next("UE")
			ku := deriveLinkKeyFromPK(&leo.Pk, &ru)
			if !bytes.Equal(refOpen(ku, cu), up) || !refSigOK(gs.gs, refGSMessage(gs, cred.TP), gs.sig) {
				t.Fatal("UE")
			}
			su := deriveUserGSKey(&gs.gs.Pk, &gs.R, &ru)
			sid := deriveSID(su, cred.TP, tok.Ju)
			c.next("GS")
			kg := deriveLinkKeyFromPK(&leo.Pk, &gs.gs.Sk)
			if !bytes.Equal(refOpen(kg, cg), gp) {
				t.Fatal("GS")
			}
			sg := deriveGSUserKey(&Ru, &gs.gs.Sk, &gs.r)
			if !bytes.Equal(sid, deriveSID(sg, cred.TP, tok.Ju)) {
				t.Fatal("key")
			}
			return c.done()
		}
	})
	measureRoles(t, "handover_S1", func() func() map[string]int64 {
		return func() map[string]int64 {
			c := newRoleClock("UE")
			var ru Fr
			ru.Random()
			Ru := rgMul(p.G0, ru)
			msg := append(append([]byte(nil), session.SID...), Ru.Serialize()...)
			tok, tin, _ := RefShowWithMessage(p, u, k, cred, attrs, attrs[:2], &Dispenser{Remaining: []uint64{2}}, msg)
			payload := append(refTokBytes(tok), msg...)
			ku := deriveLinkKeyFromPK(&next.Pk, &ru)
			ct := refSeal(ku, payload)
			c.next("LEO")
			kl := deriveLinkKeyFromPK(&Ru, &next.Sk)
			if !bytes.Equal(refOpen(kl, ct), payload) || !RefVerifyWithMessage(p, k, tok, tin, attrs[:2], nil, msg) {
				t.Fatal("S1")
			}
			kg := deriveLinkKeyFromPK(&session.GS.Pk, &next.Sk)
			cg := refSeal(kg, session.SID)
			c.next("GS")
			kg2 := deriveLinkKeyFromPK(&next.Pk, &session.GS.Sk)
			if !bytes.Equal(refOpen(kg2, cg), session.SID) {
				t.Fatal("S1 GS")
			}
			return c.done()
		}
	})
	measureRoles(t, "handover_S2", func() func() map[string]int64 {
		return func() map[string]int64 {
			c := newRoleClock("LEO")
			up := refGSPayload(g2)
			gp := append(append(append(append([]byte(nil), session.SID...), session.Ru.Serialize()...), uint64Bytes(session.TP)...), uint64Bytes(session.Ju)...)
			kg := deriveLinkKeyFromPK(&g2.gs.Pk, &session.LEO.Sk)
			cu, cg := refSeal(session.EKLU, up), refSeal(kg, gp)
			c.next("UE")
			if !bytes.Equal(refOpen(session.EKLU, cu), up) || !refSigOK(g2.gs, refGSMessage(g2, session.TP), g2.sig) {
				t.Fatal("S2 UE")
			}
			su := deriveUserGSKey(&g2.gs.Pk, &g2.R, &session.RuSecret)
			sid := deriveHandoverSID(session.SID, su, session.TP, session.Ju)
			c.next("GS")
			kg2 := deriveLinkKeyFromPK(&session.LEO.Pk, &g2.gs.Sk)
			if !bytes.Equal(refOpen(kg2, cg), gp) {
				t.Fatal("S2 GS")
			}
			sg := deriveGSUserKey(&session.Ru, &g2.gs.Sk, &g2.r)
			if !bytes.Equal(sid, deriveHandoverSID(session.SID, sg, session.TP, session.Ju)) {
				t.Fatal("S2 key")
			}
			return c.done()
		}
	})
	tok, _, _ := RefShowWithMessage(p, u, k, cred, attrs, attrs[:2], &Dispenser{Remaining: []uint64{1}}, nil)
	// Include disclosed attributes; the corrected helper now includes challenge C.
	token := len(refTokBytes(tok)) + 2*32
	fmt.Printf("WIRE20 PKTSIN token_complete_fields=%d access_UE_LEO=%d access_LEO_UE=%d access_LEO_GS=%d S1_UE_LEO=%d S1_LEO_GS=%d S2_LEO_UE=%d S2_LEO_GS=%d\n", token, token+48, len(refGSPayload(gs))+28, 48+16+28, 48+token+32+48+28, 32+28, len(refGSPayload(g2))+28, 32+48+16+28)
}

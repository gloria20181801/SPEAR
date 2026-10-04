package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
)

// CPU reconstruction of Section V-C/D. Real SE operations are included;
// propagation, durable NCC token logging and deployment policy are excluded.
func refSeal(k, p []byte) []byte {
	b, e := aes.NewCipher(k[:16])
	if e != nil {
		panic(e)
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		panic(e)
	}
	n := make([]byte, a.NonceSize())
	rand.Read(n)
	return a.Seal(n, n, p, nil)
}

func refOpen(k, c []byte) []byte {
	b, e := aes.NewCipher(k[:16])
	if e != nil {
		panic(e)
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		panic(e)
	}
	p, e := a.Open(nil, c[:a.NonceSize()], c[a.NonceSize():], nil)
	if e != nil {
		panic(e)
	}
	return p
}

func refTokBytes(t *RefToken) []byte {
	d := append(uint64Bytes(t.TP), uint64Bytes(t.K)...)
	d = append(d, uint64Bytes(t.Ju)...)
	for _, g := range t.Cu {
		d = append(d, g.Serialize()...)
	}
	for _, g := range t.Du {
		d = append(d, g.Serialize()...)
	}
	for _, g := range t.Eu {
		d = append(d, g.Serialize()...)
	}
	d = append(d, t.Fu.Serialize()...)
	d = append(d, t.TIN.Serialize()...)
	for _, g := range t.Proof.L {
		d = append(d, g.Serialize()...)
	}
	for _, s := range t.Proof.Z {
		d = append(d, s.Serialize()...)
	}
	d = append(d, t.Proof.C.Serialize()...)
	return d
}

type refGSProfile struct {
	gs     *GS
	r      Fr
	R      G
	id     string
	sig    []byte
	bindTP bool
}

func refGS(pp *PublicParams, id string, tp uint64, bind bool) *refGSProfile {
	g := GSSetup(pp)
	var r Fr
	r.Random()
	R := rgMul(pp.G0, r)
	msg := append([]byte(id), R.Serialize()...)
	if bind {
		msg = append(msg, uint64Bytes(tp)...)
	}
	sig := refSign(g, msg)
	return &refGSProfile{g, r, R, id, sig, bind}
}

func refGSMessage(g *refGSProfile, tp uint64) []byte {
	m := append([]byte(g.id), g.R.Serialize()...)
	if g.bindTP {
		m = append(m, uint64Bytes(tp)...)
	}
	return m
}

func refGSPayload(g *refGSProfile) []byte {
	d := append([]byte(g.id), g.gs.Pk.Serialize()...)
	d = append(d, g.R.Serialize()...)
	return append(d, g.sig...)
}

func refAccess(pp *PublicParams, u *UserKey, ik *IssuerKey, c *Credential, attrs []Fr, leo *LEO, gs *refGSProfile) *PkTSINSession {
	var ru Fr
	ru.Random()
	Ru := rgMul(pp.G0, ru)
	m := Ru.Serialize()
	tok, tin, _ := RefShowWithMessage(pp, u, ik, c, attrs, attrs[:2], &Dispenser{Remaining: []uint64{1}}, m)
	if !RefVerifyWithMessage(pp, ik, tok, tin, attrs[:2], nil, m) {
		panic("token")
	}
	klu := deriveLinkKeyFromPK(&Ru, &leo.Sk)
	klg := deriveLinkKeyFromPK(&gs.gs.Pk, &leo.Sk)
	suPayload := refGSPayload(gs)
	gsPayload := append(append(Ru.Serialize(), uint64Bytes(c.TP)...), uint64Bytes(tok.Ju)...)
	ctu, ctg := refSeal(klu, suPayload), refSeal(klg, gsPayload)
	ksu := deriveLinkKeyFromPK(&leo.Pk, &ru)
	kg := deriveLinkKeyFromPK(&leo.Pk, &gs.gs.Sk)
	if !bytes.Equal(refOpen(ksu, ctu), suPayload) || !bytes.Equal(refOpen(kg, ctg), gsPayload) || !refSigOK(gs.gs, refGSMessage(gs, c.TP), gs.sig) {
		panic("channel")
	}
	su := deriveUserGSKey(&gs.gs.Pk, &gs.R, &ru)
	g := deriveGSUserKey(&Ru, &gs.gs.Sk, &gs.r)
	if !bytes.Equal(su, g) {
		panic("session")
	}
	sid := deriveSID(su, c.TP, tok.Ju)
	if !bytes.Equal(sid, deriveSID(g, c.TP, tok.Ju)) {
		panic("sid")
	}
	return &PkTSINSession{LEO: leo, GS: gs.gs, GSID: gs.id, Ru: Ru, RuSecret: ru, Rgs: gs.R, RgsSecret: gs.r, TP: c.TP, Ju: tok.Ju, SID: sid, SSK: su, EKLU: ksu, EKLG: kg}
}

func refHandover1(pp *PublicParams, u *UserKey, ik *IssuerKey, c *Credential, attrs []Fr, s *PkTSINSession, next *LEO) {
	var ru Fr
	ru.Random()
	Ru := rgMul(pp.G0, ru)
	m := append(append([]byte(nil), s.SID...), Ru.Serialize()...)
	tok, tin, _ := RefShowWithMessage(pp, u, ik, c, attrs, attrs[:2], &Dispenser{Remaining: []uint64{2}}, m)
	payload := append(refTokBytes(tok), m...)
	ku := deriveLinkKeyFromPK(&next.Pk, &ru)
	ct := refSeal(ku, payload)
	kl := deriveLinkKeyFromPK(&Ru, &next.Sk)
	if !bytes.Equal(refOpen(kl, ct), payload) || !RefVerifyWithMessage(pp, ik, tok, tin, attrs[:2], nil, m) {
		panic("s1")
	}
	kg := deriveLinkKeyFromPK(&s.GS.Pk, &next.Sk)
	ctg := refSeal(kg, s.SID)
	kg2 := deriveLinkKeyFromPK(&next.Pk, &s.GS.Sk)
	if !bytes.Equal(refOpen(kg2, ctg), s.SID) {
		panic("s1gs")
	}
}

func refHandover2(s *PkTSINSession, g *refGSProfile) {
	suPayload := refGSPayload(g)
	gp := append(append(append(append([]byte(nil), s.SID...), s.Ru.Serialize()...), uint64Bytes(s.TP)...), uint64Bytes(s.Ju)...)
	kg := deriveLinkKeyFromPK(&g.gs.Pk, &s.LEO.Sk)
	cu, cg := refSeal(s.EKLU, suPayload), refSeal(kg, gp)
	kg2 := deriveLinkKeyFromPK(&s.LEO.Pk, &g.gs.Sk)
	if !bytes.Equal(refOpen(s.EKLU, cu), suPayload) || !bytes.Equal(refOpen(kg2, cg), gp) || !refSigOK(g.gs, refGSMessage(g, s.TP), g.sig) {
		panic("s2channel")
	}
	su := deriveUserGSKey(&g.gs.Pk, &g.R, &s.RuSecret)
	gg := deriveGSUserKey(&s.Ru, &g.gs.Sk, &g.r)
	if !bytes.Equal(deriveHandoverSID(s.SID, su, s.TP, s.Ju), deriveHandoverSID(s.SID, gg, s.TP, s.Ju)) {
		panic("s2key")
	}
}

func refReveal(a, b *RefToken) G {
	if !a.TIN.IsEqual(&b.TIN) || a.Ju != b.Ju || a.TP != b.TP {
		panic("not double use")
	}
	w1, w2 := refW(nilPP, a.Token), refW(nilPP, b.Token)
	d := rfSub(w1, w2)
	if d.IsZero() {
		panic("same token")
	}
	var inv Fr
	FrInv(&inv, &d)
	f := rgMul(rgSub(a.Fu, b.Fu), inv)
	return rgSub(a.Fu, rgMul(f, w1))
}

var nilPP = &PublicParams{H1: HashToFr}

func TestReferenceSessionAndHandover(t *testing.T) {
	p, u, k, c, a := pktFixture(3)
	l := LEOSetup(p)
	g := refGS(p, "GS1", 1, true)
	s := refAccess(p, u, k, c, a, l, g)
	refHandover1(p, u, k, c, a, s, LEOSetup(p))
	refHandover2(s, refGS(p, "GS2", 1, false))
	a1, _, _ := RefShowWithMessage(p, u, k, c, a, a[:2], &Dispenser{Remaining: []uint64{1}}, nil)
	a2, _, _ := RefShowWithMessage(p, u, k, c, a, a[:2], &Dispenser{Remaining: []uint64{1}}, nil)
	opened := refReveal(a1, a2)
	if !opened.IsEqual(&u.Upk) {
		t.Fatal("reveal")
	}
}

func TestPerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	for _, n := range []int{3} {
		p, u, k, c, a := pktFixture(n)
		l := LEOSetup(p)
		l2 := LEOSetup(p)
		g := refGS(p, "GS1", 1, true)
		g2 := refGS(p, "GS2", 1, false)
		s := refAccess(p, u, k, c, a, l, g)
		name := fmt.Sprintf("_n%d", n)
		measureStage(t, "RECON_session_all_roles"+name, func() func() { return func() { refAccess(p, u, k, c, a, l, g) } })
		measureStage(t, "RECON_handover_S1"+name, func() func() { return func() { refHandover1(p, u, k, c, a, s, l2) } })
		measureStage(t, "RECON_handover_S2"+name, func() func() { return func() { refHandover2(s, g2) } })
		measureStage(t, "RECON_handover_S3"+name, func() func() { return func() { refAccess(p, u, k, c, a, l2, g) } })
		tok, _, _ := RefShowWithMessage(p, u, k, c, a, a[:2], &Dispenser{Remaining: []uint64{1}}, nil)
		t.Logf("PAYLOAD token_n%d %d", n, len(refTokBytes(tok)))
	}
}

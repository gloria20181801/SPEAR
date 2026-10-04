package main

import (
	mcl "github.com/alinush/go-mcl"
	"testing"
)

func pktFixture(n int) (*PublicParams, *UserKey, *IssuerKey, *Credential, []Fr) {
	mcl.InitMclHelper(mcl.BLS12_381)
	p := Setup(n)
	u := UKeyGen(p, "U")
	ik := IKeyGen(p)
	a := make([]Fr, n)
	for i := range a {
		a[i].Random()
	}
	cr, _ := Issue(p, u, a, ik, 1, 100)
	return p, u, ik, cr, a
}

func TestAppendixReference(t *testing.T) {
	p, u, k, c, a := pktFixture(3)
	msg := []byte("bound DH share")
	tok, tin, _ := RefShowWithMessage(p, u, k, c, a, a[:2], &Dispenser{Remaining: []uint64{1}}, msg)
	if !RefVerifyWithMessage(p, k, tok, tin, a[:2], nil, msg) {
		t.Fatal("honest appendix")
	}
	var bad G
	bad.Random()
	if RefVerifyWithMessage(p, k, tok, &bad, a[:2], nil, msg) {
		t.Fatal("bad tin")
	}
	if RefVerifyWithMessage(p, k, tok, tin, a[:2], nil, []byte("bad")) {
		t.Fatal("bad msg")
	}
	tok.Fu.Random()
	if RefVerifyWithMessage(p, k, tok, tin, a[:2], nil, msg) {
		t.Fatal("bad Fu")
	}
}

func TestAppendixIssue(t *testing.T) {
	p, u, k, _, a := pktFixture(3)
	c, _ := RefIssue(p, u, a, k, 1, 100)
	tok, tin, _ := RefShowWithMessage(p, u, k, c, a, a[:2], &Dispenser{Remaining: []uint64{1}}, nil)
	if !RefVerifyWithMessage(p, k, tok, tin, a[:2], nil, nil) {
		t.Fatal("issued credential rejected")
	}
	b := [][]G{{p.G0}}
	ys := []G{u.Upk}
	pr := refLinearProve(b, ys, []Fr{u.Usk}, nil)
	ys[0].Random()
	if refLinearVerify(b, ys, pr, nil) {
		t.Fatal("mutated linear statement")
	}
}

package main

import (
	mcl "github.com/alinush/go-mcl"
	"testing"
)

func aakaFixture() (*PublicParams, *IssuingKey, *ElGamalKey, *Credential, mcl.Fr) {
	InitCurve()
	p := Setup()
	ik, eg := KeyGen(p)
	ms := make([]mcl.Fr, 4)
	for i := range ms {
		ms[i].Random()
	}
	cr := Issue(ik, p, ms)
	var beta mcl.Fr
	beta.Random()
	return p, ik, eg, cr, beta
}

type refPi0 struct {
	A [5]mcl.G1
	B [5]mcl.G2
	Z [5]mcl.Fr
	C mcl.Fr
}

func refIssueChallenge(p *PublicParams, cr *Credential, q *refPi0) mcl.Fr {
	d := []byte("AAKA-PI0-REF")
	d = append(d, cr.Sigma.Serialize()...)
	for i := 0; i < 5; i++ {
		d = append(d, cr.SigmaI[i].Serialize()...)
		d = append(d, p.X[i].Serialize()...)
		d = append(d, q.A[i].Serialize()...)
		d = append(d, q.B[i].Serialize()...)
	}
	return HashToFr(d)
}

func refIssueProof(p *PublicParams, ik *IssuingKey, cr *Credential) *refPi0 {
	q := new(refPi0)
	var a [5]mcl.Fr
	for i := range a {
		a[i].Random()
		mcl.G1Mul(&q.A[i], &cr.Sigma, &a[i])
		mcl.G2Mul(&q.B[i], &p.G2, &a[i])
	}
	q.C = refIssueChallenge(p, cr, q)
	for i := range a {
		mcl.FrMul(&q.Z[i], &q.C, &ik.X[i])
		mcl.FrAdd(&q.Z[i], &q.Z[i], &a[i])
	}
	return q
}

func refCheckIssue(p *PublicParams, cr *Credential, q *refPi0) bool {
	h := refIssueChallenge(p, cr, q)
	if !h.IsEqual(&q.C) {
		return false
	}
	for i := 0; i < 5; i++ {
		var l, r, w mcl.G1
		mcl.G1Mul(&l, &cr.Sigma, &q.Z[i])
		mcl.G1Mul(&w, &cr.SigmaI[i], &q.C)
		mcl.G1Add(&r, &q.A[i], &w)
		if !l.IsEqual(&r) {
			return false
		}
		var ll, rr, ww mcl.G2
		mcl.G2Mul(&ll, &p.G2, &q.Z[i])
		mcl.G2Mul(&ww, &p.X[i], &q.C)
		mcl.G2Add(&rr, &q.B[i], &ww)
		if !ll.IsEqual(&rr) {
			return false
		}
	}
	return true
}

func TestReferenceIssueProofRejectsMutation(t *testing.T) {
	p, ik, _, cr, _ := aakaFixture()
	q := refIssueProof(p, ik, cr)
	if !refCheckIssue(p, cr, q) {
		t.Fatal("valid")
	}
	cr.SigmaI[3].Random()
	if refCheckIssue(p, cr, q) {
		t.Fatal("bad issue accepted")
	}
}

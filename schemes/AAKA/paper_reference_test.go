package main

import (
	"bytes"
	"fmt"
	mcl "github.com/alinush/go-mcl"
	"os"
	"testing"
)

func paperFixture() (*PublicParams, *IssuingKey, *ElGamalKey, *Credential) {
	curve := mcl.BLS12_381

	mcl.InitMclHelper(curve)
	p := Setup()
	ik, eg := KeyGen(p)
	m := make([]mcl.Fr, 4)
	m[0].SetInt64(900)
	m[1].SetInt64(2000)
	m[2].SetInt64(1)
	m[3].Random()
	return p, ik, eg, Issue(ik, p, m)
}

func paperSession(p *PublicParams, c *Credential, sn *paperSN) (int, error) {
	req, u, e := paperReq(sn)
	if e != nil {
		return 0, e
	}
	res, s, e := paperRes(sn, req)
	if e != nil {
		return 0, e
	}
	k, b, e := paperSNAuth(sn, u, res)
	if e != nil || !bytes.Equal(k, s.key) {
		return 0, errPaper
	}
	q := paperPresent(p, c, b)
	cipher := paperSeal(k, paperPresBytes(q))
	raw, e := paperOpen(s.key, cipher)
	if e != nil {
		return 0, e
	}
	qq, e := paperParsePres(raw)
	if e != nil {
		return 0, e
	}
	if !qq.MVec[0].IsEqual(&c.MVec[0]) || !qq.MVec[1].IsEqual(&c.MVec[1]) || !qq.MVec[2].IsEqual(&c.MVec[2]) || !paperVerify(p, qq, s.beta) {
		return 0, errPaper
	}
	// Local registry and protected GUTI delivery; no mobile-network simulation.
	guti := mac(s.key, paperPresBytes(qq))[:16]
	registry := map[string]*Presentation{string(guti): qq}
	if registry[string(guti)] == nil {
		return 0, errPaper
	}
	ack := paperSeal(s.key, guti)
	dec, e := paperOpen(k, ack)
	if e != nil || !bytes.Equal(dec, guti) {
		return 0, errPaper
	}
	return len(req) + len(res) + len(cipher) + len(ack), nil
}

func TestPaperReferenceRoundTrip(t *testing.T) {
	p, ik, eg, c := paperFixture()
	sn := newPaperSN()
	q0 := refIssueProof(p, ik, c)
	if !Obtain(p, c) || !refCheckIssue(p, c, q0) {
		t.Fatal("issuance")
	}
	for i := 0; i < 4; i++ {
		if _, e := paperSession(p, c, sn); e != nil {
			t.Fatal(e)
		}
	}
	b := [32]byte{9}
	q := paperPresent(p, c, b)
	if !paperVerify(p, q, b) {
		t.Fatal("proof")
	}
	var shared, opened, want mcl.G1
	mcl.G1Mul(&shared, &q.C1, &eg.Sk)
	mcl.G1Sub(&opened, &q.C2, &shared)
	mcl.G1Mul(&want, &p.G1, &c.MVec[3])
	if !opened.IsEqual(&want) {
		t.Fatal("escrow roundtrip")
	}
	// Correctness of actual packet crypto, not a security audit of AAKA.
	req, u, _ := paperReq(sn)
	res, s, e := paperRes(sn, req)
	if e != nil {
		t.Fatal(e)
	}
	k, bb, e := paperSNAuth(sn, u, res)
	if e != nil || !bytes.Equal(k, s.key) || bb != s.beta {
		t.Fatal("key agreement")
	}
	enc := paperSeal(k, paperPresBytes(q))
	dec, e := paperOpen(k, enc)
	if e != nil || !bytes.Equal(dec, paperPresBytes(q)) {
		t.Fatal("packet roundtrip")
	}
	t.Logf("profile %s honest algorithms and packet round trips pass", "BLS12-381")
}

func TestPerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	p, ik, eg, c := paperFixture()
	sn := newPaperSN()
	req, u, _ := paperReq(sn)
	res, s, e := paperRes(sn, req)
	if e != nil {
		t.Fatal(e)
	}
	k, b, e := paperSNAuth(sn, u, res)
	if e != nil {
		t.Fatal(e)
	}
	q := paperPresent(p, c, b)
	wire := paperPresBytes(q)
	pi0 := refIssueProof(p, ik, c)
	measureStage(t, "PAPER_issue_with_pi0", func() func() { return func() { cc := Issue(ik, p, c.MVec); refIssueProof(p, ik, cc) } })
	measureStage(t, "PAPER_obtain_with_pi0", func() func() {
		return func() {
			if !Obtain(p, c) || !refCheckIssue(p, c, pi0) {
				t.Fatal("obtain")
			}
		}
	})
	measureStage(t, "PAPER_Req_X25519_ECIES", func() func() {
		return func() {
			if _, _, e := paperReq(sn); e != nil {
				t.Fatal(e)
			}
		}
	})
	measureStage(t, "PAPER_Res_decrypt_DH_sign", func() func() {
		return func() {
			if _, _, e := paperRes(sn, req); e != nil {
				t.Fatal(e)
			}
		}
	})
	measureStage(t, "PAPER_SNAuth_verify_DH", func() func() {
		return func() {
			if _, _, e := paperSNAuth(sn, u, res); e != nil {
				t.Fatal(e)
			}
		}
	})
	measureStage(t, "PAPER_PresGen_appendixF", func() func() { return func() { paperPresent(p, c, b) } })
	measureStage(t, "PAPER_Verify_appendixF_two_pairings", func() func() {
		return func() {
			if !paperVerify(p, q, b) {
				t.Fatal("verify")
			}
		}
	})
	measureStage(t, "PAPER_PresGen_encode_encrypt", func() func() { return func() { qq := paperPresent(p, c, b); paperSeal(k, paperPresBytes(qq)) } })
	ct := paperSeal(k, wire)
	measureStage(t, "PAPER_decrypt_decode_Verify", func() func() {
		return func() {
			raw, e := paperOpen(s.key, ct)
			if e != nil {
				t.Fatal(e)
			}
			qq, e := paperParsePres(raw)
			if e != nil || !paperVerify(p, qq, s.beta) {
				t.Fatal("decode verify", e)
			}
		}
	})
	measureStage(t, "PAPER_all_roles_local_authentication", func() func() {
		return func() {
			if _, e := paperSession(p, c, sn); e != nil {
				t.Fatal(e)
			}
		}
	})
	var want mcl.G1
	mcl.G1Mul(&want, &p.G1, &c.MVec[3])
	measureStage(t, "PAPER_open_and_one_entry_lookup", func() func() {
		return func() {
			var shared, opened mcl.G1
			mcl.G1Mul(&shared, &q.C1, &eg.Sk)
			mcl.G1Sub(&opened, &q.C2, &shared)
			if !opened.IsEqual(&want) {
				t.Fatal("open")
			}
		}
	})
	total, e := paperSession(p, c, sn)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("WIRE AAKA_%s presentation=%d encrypted_presentation=%d request=%d response=%d all_roles_payload=%d\n", "BLS12-381", len(wire), len(ct), len(req), len(res), total)
}

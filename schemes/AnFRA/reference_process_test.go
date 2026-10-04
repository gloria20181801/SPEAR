package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	mcl "github.com/alinush/go-mcl"
	"os"
	"strconv"
	"testing"
)

type refNegotiatedGS struct {
	secret    mcl.Fr
	share     mcl.G1
	timestamp int64
	signature []byte
}

func refECSign(k *ecdsa.PrivateKey, m []byte) []byte {
	h := sha256.Sum256(m)
	s, e := ecdsa.SignASN1(rand.Reader, k, h[:])
	if e != nil {
		panic(e)
	}
	return s
}

func refECVerify(k *ecdsa.PublicKey, m, s []byte) bool {
	h := sha256.Sum256(m)
	return ecdsa.VerifyASN1(k, h[:], s)
}

func refNegotiate(p RefGroupPublicKey, k *ecdsa.PrivateKey) *refNegotiatedGS {
	q := new(refNegotiatedGS)
	q.secret.Random()
	mcl.G1Mul(&q.share, &p.g, &q.secret)
	q.timestamp = GenTimestamp()
	m := append(q.share.Serialize(), []byte(strconv.FormatInt(q.timestamp, 10))...)
	q.signature = refECSign(k, m)
	if !VerifyTimestamp(q.timestamp) || !refECVerify(&k.PublicKey, m, q.signature) {
		panic("GS pre negotiation")
	}
	return q
}

func refRoam(p RefGroupPublicKey, u UserPrivateKey, gs *refNegotiatedGS, leo *ecdsa.PrivateKey, cache *refPairCache) {
	var req AccessRequest
	var ru mcl.Fr
	if cache == nil {
		req, ru = RefGenAccessRequest(p, u, "U", "HNCC", "FLEO")
	} else {
		req, ru = RefGenAccessRequestCached(p, u, "U", "HNCC", "FLEO", cache)
	}
	valid := false
	if cache == nil {
		valid = RefVerifyRequest(p, req)
	} else {
		valid = RefVerifyRequestCached(p, req, cache)
	}
	if !valid {
		panic("group signature")
	}
	ts := GenTimestamp()
	m := []byte(req.TID + "|FLEO|FGS|")
	m = append(m, req.grui.Serialize()...)
	m = append(m, gs.share.Serialize()...)
	m = append(m, []byte(strconv.FormatInt(ts, 10))...)
	sig := refECSign(leo, m)
	// The user and FGS each execute Algorithm 4 independently.
	if !VerifyTimestamp(ts) || !refECVerify(&leo.PublicKey, m, sig) {
		panic("UE response")
	}
	var ku, kg mcl.G1
	mcl.G1Mul(&ku, &gs.share, &ru)
	if !VerifyTimestamp(ts) || !refECVerify(&leo.PublicKey, m, sig) {
		panic("FGS response")
	}
	mcl.G1Mul(&kg, &req.grui, &gs.secret)
	if !ku.IsEqual(&kg) {
		panic("session keys")
	}
}

func TestReferenceCachedAndRoaming(t *testing.T) {
	RefInit()
	p, _, u, _ := RefGroupInit(2)
	cache := refCache(p)
	r, _ := RefGenAccessRequestCached(p, u[0], "U", "N", "L", cache)
	if !RefVerifyRequest(p, r) || !RefVerifyRequestCached(p, r, cache) {
		t.Fatal("cached proof")
	}
	r.MUi = append([]byte("bad"), r.MUi...)
	if RefVerifyRequestCached(p, r, cache) {
		t.Fatal("bad cached proof")
	}
	gs, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leo, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q := refNegotiate(p, gs)
	refRoam(p, u[0], q, leo, nil)
	refRoam(p, u[0], q, leo, cache)
}

func TestPerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	RefInit()
	p, k, u, _ := RefGroupInit(2)
	cache := refCache(p)
	gs, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leo, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q := refNegotiate(p, gs)
	r, _ := RefGenAccessRequest(p, u[0], "U", "N", "L")
	measureStage(t, "TYPE3_fixed_pairing_cache", func() func() { return func() { refCache(p) } })
	measureStage(t, "TYPE3_cached_user_request", func() func() { return func() { RefGenAccessRequestCached(p, u[0], "U", "N", "L", cache) } })
	measureStage(t, "TYPE3_cached_group_verify", func() func() {
		return func() {
			if !RefVerifyRequestCached(p, r, cache) {
				t.Fatal("verify")
			}
		}
	})
	measureStage(t, "TYPE3_GS_pre_negotiation", func() func() { return func() { refNegotiate(p, gs) } })
	measureStage(t, "TYPE3_roaming_all_online_roles", func() func() { return func() { refRoam(p, u[0], q, leo, nil) } })
	measureStage(t, "TYPE3_roaming_cached_both", func() func() { return func() { refRoam(p, u[0], q, leo, cache) } })
	measureStage(t, "TYPE3_reveal_with_verification_and_lookup", func() func() {
		return func() {
			if !RefVerifyRequestCached(p, r, cache) {
				t.Fatal("invalid audit")
			}
			a := RefOpen(k, r)
			if !a.IsEqual(&u[0].Ai) {
				t.Fatal("not registered")
			}
		}
	})
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mcl "github.com/alinush/go-mcl"
	"os"
	"strconv"
	"testing"
)

func TestRolePerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	RefInit()
	p, _, u, _ := RefGroupInit(2)
	cache := refCache(p)
	gkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gs := refNegotiate(p, gkey)
	measureRoles(t, "roaming_cached", func() func() map[string]int64 {
		return func() map[string]int64 {
			c := newRoleClock("UE")
			req, ru := RefGenAccessRequestCached(p, u[0], "U", "HNCC", "FLEO", cache)
			c.next("LEO")
			if !RefVerifyRequestCached(p, req, cache) {
				t.Fatal("proof")
			}
			ts := GenTimestamp()
			m := []byte(req.TID + "|FLEO|FGS|")
			m = append(m, req.grui.Serialize()...)
			m = append(m, gs.share.Serialize()...)
			m = append(m, []byte(strconv.FormatInt(ts, 10))...)
			sig := refECSign(lkey, m)
			c.next("UE")
			if !VerifyTimestamp(ts) || !refECVerify(&lkey.PublicKey, m, sig) {
				t.Fatal("UE")
			}
			var ku, kg mcl.G1
			mcl.G1Mul(&ku, &gs.share, &ru)
			c.next("GS")
			if !VerifyTimestamp(ts) || !refECVerify(&lkey.PublicKey, m, sig) {
				t.Fatal("GS")
			}
			mcl.G1Mul(&kg, &req.grui, &gs.secret)
			if !ku.IsEqual(&kg) {
				t.Fatal("key")
			}
			return c.done()
		}
	})
	req, _ := RefGenAccessRequestCached(p, u[0], "U", "HNCC", "FLEO", cache)
	// Field budget: canonical TID nonce32, identities 4+4, timestamp8, grui48, sigma3G1+6Fr.
	fmt.Printf("WIRE20 AnFRA request_fields=%d response_each_fields_min=%d response_each_fields_max=%d\n", 32+4+4+8+len(req.grui.Serialize())+3*48+6*32, 32+4+3+8+2*48+70, 32+4+3+8+2*48+72)
}

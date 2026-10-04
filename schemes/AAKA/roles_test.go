package main

import (
	"bytes"
	"os"
	"testing"
)

func TestRolePerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("set RUN_PERFORMANCE=1 via scripts/benchmark.sh")
	}
	p, _, _, cred := paperFixture()
	sn := newPaperSN()
	measureRoles(t, "access", func() func() map[string]int64 {
		return func() map[string]int64 {
			c := newRoleClock("UE")
			req, u, e := paperReq(sn)
			if e != nil {
				t.Fatal(e)
			}
			c.next("SN")
			res, s, e := paperRes(sn, req)
			if e != nil {
				t.Fatal(e)
			}
			c.next("UE")
			key, b, e := paperSNAuth(sn, u, res)
			if e != nil {
				t.Fatal(e)
			}
			q := paperPresent(p, cred, b)
			wire := paperSeal(key, paperPresBytes(q))
			c.next("SN")
			raw, e := paperOpen(s.key, wire)
			if e != nil {
				t.Fatal(e)
			}
			qq, e := paperParsePres(raw)
			if e != nil || !paperVerify(p, qq, s.beta) {
				t.Fatal("verify")
			}
			guti := mac(s.key, paperPresBytes(qq))[:16]
			registry := map[string]*Presentation{string(guti): qq}
			if registry[string(guti)] == nil {
				t.Fatal("registry")
			}
			ack := paperSeal(s.key, guti)
			c.next("UE")
			out, e := paperOpen(key, ack)
			if e != nil || !bytes.Equal(out, guti) {
				t.Fatal("ack")
			}
			return c.done()
		}
	})
}

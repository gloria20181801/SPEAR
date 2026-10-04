package spear

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/alinush/go-mcl"
	"os"
	"testing"
	"time"
)

func sampleStage(t *testing.T, name string, prepare func() func()) {
	t.Helper()
	for i := 0; i < 5; i++ {
		prepare()()
	}
	xs := make([]int64, 300)
	for i := range xs {
		fn := prepare()
		start := time.Now()
		fn()
		xs[i] = time.Since(start).Nanoseconds()
	}
	b, _ := json.Marshal(map[string]interface{}{"name": name, "samples_ns": xs})
	fmt.Println("BENCH " + string(b))
}

func TestPerformance(t *testing.T) {
	if os.Getenv("RUN_PERFORMANCE") != "1" {
		t.Skip("use scripts/benchmark.sh")
	}
	f := newSPEARFixture(t)
	f.m.SetInt64(1000000)
	sk, vk := Keygen(f.params)
	f.vk = vk
	_, cred, e := SignCred(f.params, sk, []*mcl.Fr{&f.m}, []*mcl.Fr{&f.m1, &f.m2})
	recheck(t, e)
	f.cred = cred
	acc, e := SetupSPEARPublicAccumulator(15)
	recheck(t, e)
	f.acc = *acc
	list := make([]mcl.Fr, 1024)
	for i := range list {
		list[i].SetInt64(int64(i + 1))
	}
	f.digest, _ = acc.Commit(list)
	f.cached, e = SingleNonMemPrecompute(acc, list, &f.m)
	recheck(t, e)
	cache := makeProverCache(t, f)
	a, _ := testSPEARAcceptor(t, f)
	binding := [32]byte{1}
	nonce := func() []byte { n, _, e := a.Challenge(binding, time.Minute); recheck(t, e); return n }
	complete := func(n []byte) []byte { w, e := cachedToken(t, f, cache).Finish(&f.digest, n); recheck(t, e); return w }
	sampleStage(t, "credential_issue", func() func() {
		return func() { _, _, e := SignCred(f.params, sk, []*mcl.Fr{&f.m}, []*mcl.Fr{&f.m1, &f.m2}); recheck(t, e) }
	})
	sampleStage(t, "access_UE_precompute", func() func() { return func() { cachedToken(t, f, cache) } })
	sampleStage(t, "access_UE_online_finish", func() func() {
		h := cachedToken(t, f, cache)
		n := nonce()
		return func() { _, e := h.Finish(&f.digest, n); recheck(t, e) }
	})
	sampleStage(t, "access_UE_total_cached_witness", func() func() { n := nonce(); return func() { complete(n) } })
	sampleStage(t, "access_LEO_accept", func() func() { w := complete(nonce()); return func() { _, e := a.Accept(binding, w); recheck(t, e) } })
	p1, k1, e := ed25519.GenerateKey(rand.Reader)
	recheck(t, e)
	p2, k2, e := ed25519.GenerateKey(rand.Reader)
	recheck(t, e)
	keys := map[string]ed25519.PublicKey{"GS1": p1, "GS2": p2}
	sym1 := make([]byte, 32)
	sym2 := make([]byte, 32)
	rand.Read(sym1)
	rand.Read(sym2)
	makeGS := func(id string, k ed25519.PrivateKey, sym []byte) *SPEARHandoverAuthority {
		g, e := NewSPEARHandoverAuthority(id, k, sym, keys)
		recheck(t, e)
		g.now = a.now
		return g
	}
	gs1 := makeGS("GS1", k1, sym1)
	gs2 := makeGS("GS2", k2, sym2)
	w := complete(nonce())
	record, e := a.Accept(binding, w)
	recheck(t, e)
	recheck(t, gs1.Register(*record))
	sampleStage(t, "access_GS_register", func() func() { return func() { recheck(t, gs1.Register(*record)) } })
	sampleStage(t, "access_all_roles_cached_witness", func() func() {
		return func() {
			w := complete(nonce())
			r, e := a.Accept(binding, w)
			recheck(t, e)
			recheck(t, gs1.Register(*r))
		}
	})
	for _, signed := range []bool{false, true} {
		target, name := "GS1", "same_GS"
		g := gs1
		if signed {
			target, name = "GS2", "cross_GS"
			g = gs2
		}
		issue := func() []byte {
			w, e := gs1.Issue(record.SID, target, "LEO2", time.Minute, signed)
			recheck(t, e)
			return w
		}
		sampleStage(t, "handover_"+name+"_source_issue", func() func() { return func() { issue() } })
		sampleStage(t, "handover_"+name+"_target_consume", func() func() {
			w := issue()
			if signed {
				g = makeGS("GS2", k2, sym2)
			}
			return func() { _, e := g.Consume(w, "LEO2"); recheck(t, e) }
		})
		wire := issue()
		fmt.Printf("WIRE handover_%s=%d\n", name, len(wire))
	}
	fmt.Printf("WIRE access_message=%d witness=%d\n", len(w), len(f.cached.AggregatedAlpha.Serialize())+len(f.cached.AggregatedBeta.Serialize()))
}

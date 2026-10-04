package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/alinush/go-mcl"
	"spear-artifact/protocol"
	"time"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	mcl.InitMclHelper(mcl.BLS12_381)
	params, e := spear.Setup(3)
	check(e)
	sk, vk := spear.Keygen(params)
	audit, nccShare, lraShare := spear.GenerateAuditKeys(params)
	var m, m1, m2 mcl.Fr
	m.SetInt64(1000000)
	m1.SetInt64(2026)
	m2.SetInt64(1)
	_, cred, e := spear.SignCred(params, sk, []*mcl.Fr{&m}, []*mcl.Fr{&m1, &m2})
	check(e)
	acc, e := spear.SetupSPEARPublicAccumulator(4)
	check(e)
	revoked := make([]mcl.Fr, 4)
	for i := range revoked {
		revoked[i].SetInt64(int64(i + 1))
	}
	digest, _ := acc.Commit(revoked)
	witness, e := spear.SingleNonMemPrecompute(acc, revoked, &m)
	check(e)
	cache, e := spear.NewSPEARProverCache(params, audit, cred, &m1, &m2, &m, vk, acc)
	check(e)
	revPub, revKey, e := ed25519.GenerateKey(rand.Reader)
	check(e)
	now := time.Now().Unix()
	ctx, e := spear.SPEARParameterContext(acc)
	check(e)
	state, e := spear.SignSPEARRevocation(revKey, digest, now-1, now+120, ctx)
	check(e)
	sat, e := spear.NewSPEARAcceptor(params, vk, audit, acc, revPub, []spear.SPEARCredentialPolicy{{M1: m1, M2: m2, NotBefore: now - 1, NotAfter: now + 600}}, 10*time.Minute)
	check(e)
	check(sat.InstallState(state))
	// In a deployment this binding is supplied by the authenticated session layer.
	var binding [32]byte
	_, e = rand.Read(binding[:])
	check(e)
	nonce, _, e := sat.Challenge(binding, time.Minute)
	check(e)
	token, e := spear.PrecomputeSPEARToken(acc, &digest, &m, witness)
	check(e)
	prepared, e := cache.Precompute(token, &digest)
	check(e)
	wire, e := prepared.Finish(&digest, nonce)
	check(e)
	accepted, e := sat.Accept(binding, wire)
	check(e)
	fmt.Printf("Access accepted; compact message=%d bytes; witness=%d bytes\n", len(wire), len(witness.AggregatedAlpha.Serialize())+len(witness.AggregatedBeta.Serialize()))
	p1, e := spear.SPEARAuditPartial(&accepted.C1, &nccShare)
	check(e)
	p2, e := spear.SPEARAuditPartial(&accepted.C1, &lraShare)
	check(e)
	identity, e := spear.SPEARCombineOpening(*accepted, p1, p2)
	check(e)
	var expected mcl.G1
	mcl.G1Mul(&expected, &audit.IdentityBase, &m)
	if !identity.IsEqual(&expected) {
		panic("opening mismatch")
	}
	fmt.Println("Two-share opening matches the enrolled identity")
	pub1, key1, e := ed25519.GenerateKey(rand.Reader)
	check(e)
	pub2, key2, e := ed25519.GenerateKey(rand.Reader)
	check(e)
	keys := map[string]ed25519.PublicKey{"GS1": pub1, "GS2": pub2}
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	gs1, e := spear.NewSPEARHandoverAuthority("GS1", key1, k1, keys)
	check(e)
	gs2, e := spear.NewSPEARHandoverAuthority("GS2", key2, k2, keys)
	check(e)
	check(gs1.Register(*accepted))
	same, e := gs1.Issue(accepted.SID, "GS1", "LEO2", time.Minute, false)
	check(e)
	_, e = gs1.Consume(same, "LEO2")
	check(e)
	cross, e := gs1.Issue(accepted.SID, "GS2", "LEO3", time.Minute, true)
	check(e)
	_, e = gs2.Consume(cross, "LEO3")
	check(e)
	if _, e = gs2.Consume(cross, "LEO3"); e == nil {
		panic("replay accepted")
	}
	fmt.Println("Same-GS and cross-GS handover accepted; repeated cookie rejected")
}

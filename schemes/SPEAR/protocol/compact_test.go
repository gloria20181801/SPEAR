package spear

import (
	"bytes"
	"github.com/alinush/go-mcl"
	"testing"
	"time"
)

func TestCompactAcceptanceAndFreshness(t *testing.T) {
	f := newSPEARFixture(t)
	a, _ := testSPEARAcceptor(t, f)
	binding := [32]byte{8}
	cache := makeProverCache(t, f)
	fresh := func() []byte {
		n, _, e := a.Challenge(binding, time.Minute)
		recheck(t, e)
		w, e := cachedToken(t, f, cache).Finish(&f.digest, n)
		recheck(t, e)
		return w
	}
	w := fresh()
	if len(w) != 1234 {
		t.Fatalf("compact message length: %d", len(w))
	}
	if _, e := a.Accept(binding, w); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Accept(binding, w); e == nil {
		t.Fatal("replay accepted")
	}
	for i := 1; i < 25; i++ {
		wire := fresh()
		fields, e := splitLengthPrefixed(wire, 25)
		recheck(t, e)
		fields[i][len(fields[i])-1] ^= 1
		if _, e := a.Accept(binding, appendBytes(fields...)); e == nil {
			t.Fatalf("modified field %d accepted", i)
		}
	}
	for _, tag := range []string{"SPEAR-A-WIRE-2", "SPEAR-A-WIRE-3"} {
		wire := fresh()
		fields, e := splitLengthPrefixed(wire, 25)
		recheck(t, e)
		fields[0] = []byte(tag)
		if _, e := UnmarshalSPEAR(appendBytes(fields...)); e == nil {
			t.Fatal("unsupported encoding accepted")
		}
	}
	n := make([]byte, 32)
	h := cachedToken(t, f, cache)
	copyHandle := *h
	_, e := h.Finish(&f.digest, n)
	recheck(t, e)
	if _, e := copyHandle.Finish(&f.digest, n); e == nil {
		t.Fatal("copied token reused")
	}
	wrong := f.digest
	mcl.G1Add(&wrong, &wrong, &f.params.G1)
	h = cachedToken(t, f, cache)
	if _, e := h.Finish(&wrong, n); e == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, e := h.Finish(&f.digest, n); e == nil {
		t.Fatal("failed token reused")
	}
	w1, e := cachedToken(t, f, cache).Finish(&f.digest, n)
	recheck(t, e)
	w2, e := cachedToken(t, f, cache).Finish(&f.digest, n)
	recheck(t, e)
	if bytes.Equal(w1, w2) {
		t.Fatal("proof randomness reused")
	}
}

func TestPairingCacheAgreement(t *testing.T) {
	f := newSPEARFixture(t)
	a, _ := testSPEARAcceptor(t, f)
	wire := accessWire(t, f, a, [32]byte{9})
	m, e := UnmarshalSPEAR(wire)
	recheck(t, e)
	if !a.verifyOwned(m, &a.policyBases[0]) {
		t.Fatal("cached verification")
	}
	a.verifierCache = nil
	if !a.verifyOwned(m, &a.policyBases[0]) {
		t.Fatal("uncached verification")
	}
}

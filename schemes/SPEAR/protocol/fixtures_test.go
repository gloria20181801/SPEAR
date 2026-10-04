package spear

import (
	"github.com/accumulators-agg/bp/bpacc"
	mcl "github.com/alinush/go-mcl"
	"testing"
)

type spearFixture struct {
	params    *Params
	vk        *VerificationKey
	audit     *AuditPublicKey
	cred      *Credential
	acc       bpacc.BpAcc
	m1, m2, m mcl.Fr
	digest    mcl.G1
	cached    *SingleNonMemCachedWitness
	nonce     []byte
}

// Tiny in-memory test setup. Known test trapdoor; never a production setup.
// Does not generate/read the project's large SRS files or run scalability tests.
func newSPEARFixture(t testing.TB) *spearFixture {
	t.Helper()
	mcl.InitMclHelper(mcl.BLS12_381)
	f := &spearFixture{nonce: []byte("spear-test-session")}
	var err error
	f.params, err = Setup(3)
	if err != nil {
		t.Fatal(err)
	}
	sk, vk := Keygen(f.params)
	f.vk = vk
	f.audit, _, _ = GenerateAuditKeys(f.params)
	f.m1.SetInt64(2026)
	f.m2.SetInt64(1001)
	f.m.SetInt64(123)
	_, f.cred, err = SignCred(f.params, sk, []*mcl.Fr{&f.m}, []*mcl.Fr{&f.m1, &f.m2})
	if err != nil {
		t.Fatal(err)
	}
	f.acc.Setup(3, "SPEAR-UNIT-TEST-ONLY")
	f.acc.A = make([]mcl.G1, 1)
	f.acc.B = make([]mcl.G2, 1)
	f.acc.PedVK = make([]mcl.G2, 1)
	f.acc.A[0].HashAndMapTo([]byte("SPEAR-TEST-U"))
	f.acc.B[0].HashAndMapTo([]byte("SPEAR-TEST-V"))
	f.acc.PedVK[0].HashAndMapTo([]byte("SPEAR-TEST-P"))
	revoked := make([]mcl.Fr, 4)
	for i := range revoked {
		revoked[i].SetInt64(int64(i + 1))
	}
	f.digest, _ = f.acc.Commit(revoked)
	f.cached, err = SingleNonMemPrecompute(&f.acc, revoked, &f.m)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *spearFixture) token(t testing.TB) *SPEAROneTimeToken {
	t.Helper()
	token, err := PrecomputeSPEARToken(&f.acc, &f.digest, &f.m, f.cached)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

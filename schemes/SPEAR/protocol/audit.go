package spear

import "github.com/alinush/go-mcl"

// GenerateAuditKeys demonstrates two-share setup in a single research process.
// Keep the returned shares with separate authorities; only the public key is
// passed to the prover and satellite. This is not a distributed key ceremony.
func GenerateAuditKeys(params *Params) (*AuditPublicKey, mcl.Fr, mcl.Fr) {
	var ncc, lra mcl.Fr
	ncc.Random()
	lra.Random()
	var q1, q2, j mcl.G1
	mcl.G1Mul(&q1, &params.G1, &ncc)
	mcl.G1Mul(&q2, &params.G1, &lra)
	mcl.G1Add(&q1, &q1, &q2)
	j.HashAndMapTo([]byte("SPEAR-AUDIT-IDENTITY-BASE"))
	return &AuditPublicKey{Gamma: q1, IdentityBase: j}, ncc, lra
}

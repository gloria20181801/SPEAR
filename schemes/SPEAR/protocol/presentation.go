package spear

import (
	"github.com/accumulators-agg/bp/bpacc"
	mcl "github.com/alinush/go-mcl"
	"sync"
)

// Neither the unmasked signature component nor its masking point is public.
type SPEARAccessMessage struct {
	RSat                 []byte
	M1, M2               mcl.Fr
	HPrime, SBar, C1, C2 mcl.G1
	Kappa                mcl.G2
	Proof                SPEARProof
}

type SPEARProof struct {
	compact                bool // Set only by the compact wire decoder; commitments are reconstructed.
	C                      mcl.Fr
	TKappa                 mcl.G2
	TC1, TC2               mcl.G1
	TNM                    SingleNonMemCommitment
	ZM3, ZRPrime, ZRDouble mcl.Fr
	ZNM                    SingleNonMemResponse
}

// Copies of a token handle share the same consumption state.
// Keep this handle in memory; never serialize its secret masks.
type SPEAROneTimeToken struct{ state *spearTokenState }

type spearTokenState struct {
	mu      sync.Mutex
	token   *SingleNonMemFusedToken
	binding [32]byte
}

func spearAccContext(acc *bpacc.BpAcc) []byte {
	return appendBytes([]byte("SPEAR-OPTION-A-ACC-v1"), acc.G.Serialize(), acc.H.Serialize(),
		acc.VK[0].Serialize(), acc.VK[1].Serialize(), acc.PedVK[0].Serialize(),
		acc.A[0].Serialize(), acc.B[0].Serialize())
}

func spearAccReady(acc *bpacc.BpAcc) bool {
	return acc != nil && len(acc.VK) >= 2 && len(acc.PedVK) > 0 && len(acc.A) > 0 && len(acc.B) > 0 &&
		acc.H.IsEqual(&acc.VK[0]) && !acc.G.IsZero() && !acc.H.IsZero() &&
		!acc.A[0].IsZero() && !acc.B[0].IsZero() && !acc.PedVK[0].IsZero()
}

func PrecomputeSPEARToken(acc *bpacc.BpAcc, accumulator *mcl.G1, m3 *mcl.Fr, cached *SingleNonMemCachedWitness) (*SPEAROneTimeToken, error) {
	if !spearAccReady(acc) || accumulator == nil || m3 == nil || cached == nil {
		return nil, ErrInvalidRequest
	}
	token, err := SingleNonMemPrecomputeFusedToken(acc, accumulator, m3, cached)
	if err != nil {
		return nil, err
	}
	binding := HashBytes(appendBytes(spearAccContext(acc), accumulator.Serialize(), m3.Serialize()))
	return &SPEAROneTimeToken{state: &spearTokenState{token: token, binding: binding}}, nil
}

func (handle *SPEAROneTimeToken) take(acc *bpacc.BpAcc, digest *mcl.G1, m *mcl.Fr) (*SingleNonMemFusedToken, error) {
	if handle == nil || handle.state == nil {
		return nil, ErrInvalidRequest
	}
	state := handle.state
	state.mu.Lock()
	defer state.mu.Unlock()
	binding := HashBytes(appendBytes(spearAccContext(acc), digest.Serialize(), m.Serialize()))
	if state.token == nil || state.binding != binding {
		return nil, ErrInvalidRequest
	}
	token := state.token
	state.token = nil // Consume before proving, including a subsequent failure.
	return token, nil
}

func spearVerifyCached(acc *bpacc.BpAcc, stmt *JointNIZKStatement, proof *SPEARProof, cache *spearVerifierCache, policy *mcl.G2) bool {
	if acc == nil || stmt == nil || proof == nil || len(stmt.VK.Beta) < 3 {
		return false
	}
	if proof.TNM.ZKProof.reconstruct {
		local := *proof
		local.TNM.ZKProof.R2 = append([]mcl.G1(nil), proof.TNM.ZKProof.R2...)
		proof = &local
	}
	if !proof.ZNM.ZPedersen.IsEqual(&proof.TNM.ZKProof.SR) {
		return false
	}
	if !receiverCredentialPairing(stmt, cache) {
		return false
	}

	var nc, c1, c2 mcl.Fr
	mcl.FrNeg(&nc, &proof.C)
	mcl.FrMul(&c1, &proof.C, &stmt.M1)
	mcl.FrMul(&c2, &proof.C, &stmt.M2)
	var tKappaHat mcl.G2
	if policy == nil {
		mcl.G2MulVec(&tKappaHat, []mcl.G2{stmt.VK.Beta[0], stmt.G2, stmt.Kappa, stmt.VK.Alpha, stmt.VK.Beta[1], stmt.VK.Beta[2]}, []mcl.Fr{proof.ZM3, proof.ZRPrime, nc, proof.C, c1, c2})
	} else {
		var hidden mcl.G2
		mcl.G2Sub(&hidden, &stmt.Kappa, policy)
		mcl.G2MulVec(&tKappaHat, []mcl.G2{stmt.VK.Beta[0], stmt.G2, hidden}, []mcl.Fr{proof.ZM3, proof.ZRPrime, nc})
	}

	var tC1Hat, tC2Hat mcl.G1
	mcl.G1MulVec(&tC1Hat, []mcl.G1{stmt.G1, stmt.C1}, []mcl.Fr{proof.ZRDouble, nc})
	mcl.G1MulVec(&tC2Hat, []mcl.G1{stmt.AuditPK, stmt.AuditIdentityBase, stmt.C2}, []mcl.Fr{proof.ZRDouble, proof.ZM3, nc})

	nmOK := singleNonMemVerifyFusedCached(acc, &stmt.Accumulator, &proof.TNM, &proof.ZNM, &proof.ZM3, &proof.C, cache)
	challengeHat := spearChallenge(acc, stmt, &tKappaHat, &tC1Hat, &tC2Hat, &proof.TNM)
	return nmOK && proof.C.IsEqual(&challengeHat) && (proof.compact || (proof.TKappa.IsEqual(&tKappaHat) && proof.TC1.IsEqual(&tC1Hat) && proof.TC2.IsEqual(&tC2Hat)))
}

func spearCredentialPairing(stmt *JointNIZKStatement) bool {
	if stmt.HPrime.IsZero() {
		return false
	}
	var negativeS mcl.G1
	mcl.G1Neg(&negativeS, &stmt.SPrime)
	var product mcl.GT
	mcl.MillerLoopVec(&product, []mcl.G1{stmt.HPrime, negativeS}, []mcl.G2{stmt.Kappa, stmt.G2})
	mcl.FinalExp(&product, &product)
	return product.IsOne()
}

func spearChallenge(acc *bpacc.BpAcc, stmt *JointNIZKStatement, tk *mcl.G2, t1, t2 *mcl.G1, nm *SingleNonMemCommitment) mcl.Fr {
	return HashToFr(appendBytes(spearChallengeParts(acc, stmt, tk, t1, t2, nm)...))
}

func spearChallengeParts(acc *bpacc.BpAcc, stmt *JointNIZKStatement, tk *mcl.G2, t1, t2 *mcl.G1, nm *SingleNonMemCommitment) [][]byte {
	parts := [][]byte{[]byte("SPEAR-JOINT-NIZK-OPTION-A-v2"), spearAccContext(acc), stmt.RSat,
		stmt.M1.Serialize(), stmt.M2.Serialize(), stmt.HPrime.Serialize(), stmt.SPrime.Serialize(),
		stmt.Kappa.Serialize(), stmt.C1.Serialize(), stmt.C2.Serialize(), stmt.Accumulator.Serialize(),
		stmt.VK.G2.Serialize(), stmt.VK.Alpha.Serialize(), stmt.AuditPK.Serialize(),
		stmt.AuditIdentityBase.Serialize(), stmt.G1.Serialize(), stmt.G2.Serialize()}
	for i := range stmt.VK.Beta {
		parts = append(parts, stmt.VK.Beta[i].Serialize())
	}
	// Hash all first-round values directly: the forking point binds the actual
	// commitments without a second commitment-digest collision assumption.
	parts = append(parts, tk.Serialize(), t1.Serialize(), t2.Serialize(),
		nm.PedersenCom.Serialize(), nm.TPedersen.Serialize())
	n := &nm.ZKProof
	parts = append(parts, n.ABar[0].Serialize(), n.ABar[1].Serialize(),
		n.BBar[0].Serialize(), n.BBar[1].Serialize(), n.R1.Serialize(),
		n.R2[0].Serialize(), n.R2[1].Serialize(), n.R3.Serialize())
	return parts
}

func spearKappaMSM(params *Params, vk *VerificationKey, m1, m2, m3, r *mcl.Fr) mcl.G2 {
	var out mcl.G2
	mcl.G2MulVec(&out, []mcl.G2{vk.Beta[1], vk.Beta[2], vk.Beta[0], params.G2}, []mcl.Fr{*m1, *m2, *m3, *r})
	mcl.G2Add(&out, &out, &vk.Alpha)
	return out
}

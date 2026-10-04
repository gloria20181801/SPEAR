package spear

import (
	"encoding/binary"
	"github.com/accumulators-agg/bp/bpacc"
	mcl "github.com/alinush/go-mcl"
	"sync"
)

// SPEARFullToken moves all nonce-independent first-round work offline.
// Copies of this opaque handle share one consumption state. Never serialize it.
// No satellite nonce is needed during precomputation.
type SPEARFullToken struct{ state *spearFullState }

type spearFullState struct {
	transcript, wire []byte
	transcriptNonce  int
	wireOffsets      []int
	mu               sync.Mutex
	used             bool
	acc              bpacc.BpAcc
	stmt             JointNIZKStatement
	wit              JointNIZKWitness
	masks            [3]mcl.Fr
	nm               *SingleNonMemProverState
	proof            SPEARProof
}

func precomputeSPEARFullTokenCached(params *Params, auditKey *AuditPublicKey, cred *Credential, m1 *mcl.Fr, m2 *mcl.Fr, m3 *mcl.Fr, credVK *VerificationKey, acc *bpacc.BpAcc, oneTime *SPEAROneTimeToken, accumulator *mcl.G1, fixed *SPEARProverCache) (*SPEARFullToken, error) {
	rSat := make([]byte, 32) // placeholder; never hashed as the online challenge
	if params == nil || auditKey == nil || cred == nil || m1 == nil || m2 == nil || m3 == nil || credVK == nil || !spearAccReady(acc) || oneTime == nil || accumulator == nil {
		return nil, ErrInvalidRequest
	}
	if len(credVK.Beta) != 3 {
		return nil, ErrInvalidRequest
	}
	if len(rSat) == 0 || cred.H.IsZero() || !params.G2.IsEqual(&credVK.G2) {
		return nil, ErrInvalidRequest
	}
	token, err := oneTime.take(acc, accumulator, m3)
	if err != nil {
		return nil, err
	}
	// Drop references after use; Go does not guarantee secure memory erasure.

	var rCred mcl.Fr
	for rCred.IsZero() {
		rCred.Random()
	}
	var hPrime mcl.G1
	mcl.G1Mul(&hPrime, &cred.H, &rCred)
	var sPrime mcl.G1
	mcl.G1Mul(&sPrime, &cred.S, &rCred)

	var rPrime mcl.Fr
	rPrime.Random()
	var kappa mcl.G2
	if fixed == nil {
		kappa = spearKappaMSM(params, credVK, m1, m2, m3, &rPrime)
	} else {
		mcl.G2Mul(&kappa, &params.G2, &rPrime)
		mcl.G2Add(&kappa, &kappa, &fixed.kappaBase)
	}
	var signatureMask mcl.G1
	mcl.G1Mul(&signatureMask, &hPrime, &rPrime)
	mcl.G1Add(&sPrime, &sPrime, &signatureMask) // SBar; discard the separate mask.

	var rDoublePrime mcl.Fr
	rDoublePrime.Random()
	var c1 mcl.G1
	mcl.G1Mul(&c1, &params.G1, &rDoublePrime)
	var auditBlind mcl.G1
	mcl.G1Mul(&auditBlind, &auditKey.Gamma, &rDoublePrime)
	var encodedM3 mcl.G1
	if fixed == nil {
		mcl.G1Mul(&encodedM3, &auditKey.IdentityBase, m3)
	} else {
		encodedM3 = fixed.encodedIdentity
	}
	var c2 mcl.G1
	mcl.G1Add(&c2, &auditBlind, &encodedM3)

	stmt := JointNIZKStatement{
		RSat:              append([]byte{}, rSat...),
		M1:                *m1,
		M2:                *m2,
		HPrime:            hPrime,
		SPrime:            sPrime,
		Kappa:             kappa,
		C1:                c1,
		C2:                c2,
		Accumulator:       *accumulator,
		VK:                *credVK,
		AuditPK:           auditKey.Gamma,
		AuditIdentityBase: auditKey.IdentityBase,
		G1:                params.G1,
		G2:                params.G2,
	}
	wit := JointNIZKWitness{M3: *m3, RPrime: rPrime, RDoublePrime: rDoublePrime}
	var rhoM3, rhoRPrime, rhoRDouble mcl.Fr
	rhoM3.Random()
	rhoRPrime.Random()
	rhoRDouble.Random()

	var tKappa mcl.G2
	mcl.G2MulVec(&tKappa, []mcl.G2{stmt.VK.Beta[0], stmt.G2}, []mcl.Fr{rhoM3, rhoRPrime})

	var tC1 mcl.G1
	mcl.G1Mul(&tC1, &stmt.G1, &rhoRDouble)

	var tC2 mcl.G1
	mcl.G1MulVec(&tC2, []mcl.G1{stmt.AuditPK, stmt.AuditIdentityBase}, []mcl.Fr{rhoRDouble, rhoM3})

	// Share BOTH the challenge and the mask for rho with the inner proof.
	tNM := &SingleNonMemCommitment{PedersenCom: token.PedersenCom,
		TPedersen: singlePedersenCommitment(acc, &rhoM3, &token.RR), ZKProof: token.commitmentProof()}
	nmState := &SingleNonMemProverState{PedersenRandom: token.PedersenRandom, RhoPedersen: token.RR, FusedToken: token}

	// Copy only public accumulator fields. No caller-owned slices survive.
	frozen := bpacc.BpAcc{G: acc.G, H: acc.H, VK: append([]mcl.G2(nil), acc.VK[:2]...), A: append([]mcl.G1(nil), acc.A[:1]...), B: append([]mcl.G2(nil), acc.B[:1]...), PedVK: append([]mcl.G2(nil), acc.PedVK[:1]...)}
	stmt.VK.Beta = append([]mcl.G2(nil), stmt.VK.Beta...)
	state := &spearFullState{acc: frozen, stmt: stmt, wit: wit, masks: [3]mcl.Fr{rhoM3, rhoRPrime, rhoRDouble}, nm: nmState, proof: SPEARProof{TKappa: tKappa, TC1: tC1, TC2: tC2, TNM: *tNM}}

	pp := &state.proof
	state.transcript = appendBytes(spearChallengeParts(&state.acc, &state.stmt, &pp.TKappa, &pp.TC1, &pp.TC2, &pp.TNM)...)
	state.transcriptNonce = spearFieldOffsets(state.transcript)[2]
	mm := SPEARAccessMessage{RSat: stmt.RSat, M1: stmt.M1, M2: stmt.M2, HPrime: stmt.HPrime, SBar: stmt.SPrime, C1: stmt.C1, C2: stmt.C2, Kappa: stmt.Kappa, Proof: *pp}
	state.wire = marshalSPEAROwned(&mm)
	state.wireOffsets = spearFieldOffsets(state.wire)
	return &SPEARFullToken{state: state}, nil
}

// finishExpanded consumes even on failure and returns only canonical public bytes.
// The online nonce and current authenticated digest are never preselected offline.
func (h *SPEARFullToken) finishExpanded(currentD *mcl.G1, nonce []byte) ([]byte, error) {
	if h == nil || h.state == nil {
		return nil, ErrInvalidRequest
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used {
		return nil, ErrInvalidRequest
	}
	s.used = true
	defer func() {
		if s.nm != nil && s.nm.FusedToken != nil {
			*s.nm.FusedToken = SingleNonMemFusedToken{}
		}
		s.nm = nil
		s.wit = JointNIZKWitness{}
		s.masks = [3]mcl.Fr{}
		s.proof = SPEARProof{}
		s.transcript = nil
		s.wire = nil
		s.wireOffsets = nil
	}()
	if currentD == nil || len(nonce) != 32 || !currentD.IsEqual(&s.stmt.Accumulator) {
		return nil, ErrInvalidRequest
	}
	s.stmt.RSat = append([]byte(nil), nonce...)
	p := &s.proof
	copy(s.transcript[s.transcriptNonce:s.transcriptNonce+32], nonce)
	p.C = HashToFr(s.transcript)
	p.ZM3 = frResponse(&s.masks[0], &p.C, &s.wit.M3)
	p.ZRPrime = frResponse(&s.masks[1], &p.C, &s.wit.RPrime)
	p.ZRDouble = frResponse(&s.masks[2], &p.C, &s.wit.RDoublePrime)
	p.ZNM = SingleNonMemRespondFused(s.nm, &p.C, &p.TNM.ZKProof)
	st := &s.stmt
	m := SPEARAccessMessage{RSat: st.RSat, M1: st.M1, M2: st.M2, HPrime: st.HPrime, SBar: st.SPrime, C1: st.C1, C2: st.C2, Kappa: st.Kappa, Proof: *p}
	out := append([]byte(nil), s.wire...)
	copy(out[s.wireOffsets[1]:s.wireOffsets[1]+32], nonce)
	for i, v := range spearWireElements(&m) {
		if _, ok := v.(*mcl.Fr); ok {
			b := v.Serialize()
			copy(out[s.wireOffsets[i+2]:s.wireOffsets[i+2]+len(b)], b)
		}
	}
	return out, nil
}

// Internal canonical templates only, never an untrusted-input parser.
func spearFieldOffsets(data []byte) []int {
	var out []int
	for at := 0; at < len(data); {
		n := int(binary.BigEndian.Uint32(data[at : at+4]))
		out = append(out, at+4)
		at += 4 + n
	}
	return out
}

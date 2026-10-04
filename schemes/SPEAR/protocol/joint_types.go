package spear

import (
	"github.com/accumulators-agg/bp/bpacc"
	mcl "github.com/alinush/go-mcl"
)

type SingleNonMemCommitment struct {
	PedersenCom mcl.G2
	TPedersen   mcl.G2
	ZKProof     SingleZKNonMemProof
}

type SingleNonMemResponse struct {
	ZPedersen mcl.Fr
}

type SingleNonMemProverState struct {
	PedersenRandom mcl.Fr
	RhoPedersen    mcl.Fr
	FusedToken     *SingleNonMemFusedToken
}

type SingleNonMemCachedWitness struct {
	Proof           bpacc.NonMemProof
	AggregatedAlpha mcl.G2
	AggregatedBeta  mcl.G1
}

type SingleNonMemFusedToken struct {
	PedersenCom    mcl.G2
	PedersenRandom mcl.Fr
	ABar           []mcl.G2
	BBar           []mcl.G1
	R1             mcl.G2
	R2             []mcl.G1
	R3             mcl.GT
	Tau            []mcl.Fr
	Delta3         mcl.Fr
	Delta4         mcl.Fr
	RR             mcl.Fr
	RTau           []mcl.Fr
	RDelta3        mcl.Fr
	RDelta4        mcl.Fr
}

type SingleZKNonMemProof struct {
	reconstruct bool // private compact-decoder flag; use only inside the fused outer verifier
	ABar        []mcl.G2
	BBar        []mcl.G1
	R1          mcl.G2
	R2          []mcl.G1
	R3          mcl.GT
	SR          mcl.Fr
	STau        []mcl.Fr
	SDelta3     mcl.Fr
	SDelta4     mcl.Fr
}

type JointNIZKStatement struct {
	RSat              []byte
	M1                mcl.Fr
	M2                mcl.Fr
	HPrime            mcl.G1
	SPrime            mcl.G1
	Kappa             mcl.G2
	C1                mcl.G1
	C2                mcl.G1
	Accumulator       mcl.G1
	VK                VerificationKey
	AuditPK           mcl.G1
	AuditIdentityBase mcl.G1
	G1                mcl.G1
	G2                mcl.G2
}

type JointNIZKWitness struct {
	M3           mcl.Fr
	RPrime       mcl.Fr
	RDoublePrime mcl.Fr
}

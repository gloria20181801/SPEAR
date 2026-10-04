package main

import (
	mcl "github.com/alinush/go-mcl"
)

const ATTR_NUM = 4

type PublicParams struct {
	G1 mcl.G1
	G2 mcl.G2
	GT mcl.GT
	P  mcl.Fr
	X  []mcl.G2
	H  mcl.G1
}

type IssuingKey struct {
	X []mcl.Fr
}

type ElGamalKey struct {
	Pk mcl.G1
	Sk mcl.Fr
}

type Credential struct {
	MVec   []mcl.Fr
	Sigma  mcl.G1
	SigmaI []mcl.G1
}

type ZKPProof struct {
	Y1      mcl.G1
	Y4      mcl.G1
	C       mcl.Fr
	A_prime mcl.Fr
	B_prime mcl.Fr
	Y2      mcl.G1
	Y3      mcl.G1
}

type Presentation struct {
	MVec       []mcl.Fr
	SigmaBar   mcl.G1
	SigmaPrime mcl.G1
	SigmaHatI  []mcl.G1
	C1         mcl.G1
	C2         mcl.G1
	A          mcl.G1
	B          mcl.Fr
	Pi         ZKPProof
	TraceTag   []byte
}

func InitCurve() {
	mcl.InitMclHelper(mcl.BLS12_381)
}

package spear

import (
	"crypto/sha256"
	mcl "github.com/alinush/go-mcl"
)

func frResponse(rho *mcl.Fr, challenge *mcl.Fr, witness *mcl.Fr) mcl.Fr {
	var cw mcl.Fr
	mcl.FrMul(&cw, challenge, witness)
	var out mcl.Fr
	mcl.FrAdd(&out, rho, &cw)
	return out
}

func HashBytes(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

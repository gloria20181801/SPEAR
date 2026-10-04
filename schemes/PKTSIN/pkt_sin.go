package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

type LEO struct {
	Pk         G
	Sk         Fr
	SeenTokens map[string]bool
}

type GS struct {
	Pk    G
	Sk    Fr
	DskGS ed25519.PrivateKey
	DpkGS ed25519.PublicKey
}

func LEOSetup(pp *PublicParams) *LEO {
	leo := &LEO{SeenTokens: make(map[string]bool)}
	leo.Sk.Random()
	GMul(&leo.Pk, &pp.G0, &leo.Sk)
	return leo
}

func GSSetup(pp *PublicParams) *GS {
	gs := &GS{}
	gs.Sk.Random()
	GMul(&gs.Pk, &pp.G0, &gs.Sk)
	dpk, dsk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	gs.DpkGS = dpk
	gs.DskGS = dsk
	return gs
}

package main

import (
	"crypto/ed25519"
)

func refSign(g *GS, m []byte) []byte { return ed25519.Sign(g.DskGS, m) }

func refSigOK(g *GS, m, s []byte) bool { return ed25519.Verify(g.DpkGS, m, s) }

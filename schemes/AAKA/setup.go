package main

import (
	mcl "github.com/alinush/go-mcl"
)

func Setup() *PublicParams {
	pars := new(PublicParams)
	pars.G1.Random()
	pars.G2.Random()
	pars.P.SetByCSPRNG()

	var gtUnit mcl.GT
	mcl.Pairing(&gtUnit, &pars.G1, &pars.G2)
	pars.GT = gtUnit
	return pars
}

func KeyGen(pars *PublicParams) (*IssuingKey, *ElGamalKey) {
	ik := new(IssuingKey)
	ik.X = make([]mcl.Fr, ATTR_NUM+1)
	pars.X = make([]mcl.G2, ATTR_NUM+1)
	for i := 0; i <= ATTR_NUM; i++ {
		ik.X[i].Random()
		mcl.G2Mul(&pars.X[i], &pars.G2, &ik.X[i])
	}

	egKey := new(ElGamalKey)
	egKey.Sk.Random()
	mcl.G1Mul(&egKey.Pk, &pars.G1, &egKey.Sk)
	pars.H = egKey.Pk

	return ik, egKey
}

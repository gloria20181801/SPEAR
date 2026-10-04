package main

import (
	"fmt"
	mcl "github.com/alinush/go-mcl"
	"strconv"
)

// Fixed pairings explicitly identified as cacheable in AnFRA p6.
type refPairCache struct{ hw, hg, gg mcl.GT }

func refCache(p RefGroupPublicKey) *refPairCache {
	c := new(refPairCache)
	mcl.Pairing(&c.hw, &p.h, &p.w2)
	mcl.Pairing(&c.hg, &p.h, &p.g2)
	mcl.Pairing(&c.gg, &p.g, &p.g2)
	return c
}

func RefGenAccessRequestCached(gpk RefGroupPublicKey, gsk UserPrivateKey, userID, homeNCCID, fleoID string, cached *refPairCache) (AccessRequest, mcl.Fr) {
	rUi := RandomZpStar()

	var grui mcl.G1
	mcl.G1Mul(&grui, &gpk.g, &rUi)

	var tidNonce mcl.Fr
	tidNonce.Random()
	tid := fmt.Sprintf("%x", tidNonce.Serialize())
	ts3 := GenTimestamp()
	mData := []byte(tid + "|" + fleoID + "|" + homeNCCID + "|" + string(G1ToBytes(grui)) + "|" + strconv.FormatInt(ts3, 10))

	alpha := RandomZpStar()
	beta := RandomZpStar()
	ra := RandomZpStar()
	rb := RandomZpStar()
	rx := RandomZpStar()
	rd1 := RandomZpStar()
	rd2 := RandomZpStar()

	var delta1 mcl.Fr
	mcl.FrMul(&delta1, &gsk.xi, &alpha)
	var delta2 mcl.Fr
	mcl.FrMul(&delta2, &gsk.xi, &beta)

	var T1, T2, T3 mcl.G1
	mcl.G1Mul(&T1, &gpk.u, &alpha)
	mcl.G1Mul(&T2, &gpk.v, &beta)
	var alphaAddBeta mcl.Fr
	mcl.FrAdd(&alphaAddBeta, &alpha, &beta)
	mcl.G1Mul(&T3, &gpk.h, &alphaAddBeta)
	mcl.G1Add(&T3, &T3, &gsk.Ai)

	var R1, R2 mcl.G1
	mcl.G1Mul(&R1, &gpk.u, &ra)
	mcl.G1Mul(&R2, &gpk.v, &rb)

	tmpg2 := gpk.g2
	var eT3g mcl.GT
	mcl.Pairing(&eT3g, &T3, &tmpg2)
	var rxET3g mcl.GT
	mcl.GTPow(&rxET3g, &eT3g, &rx)

	var raAddRb, negRaRb mcl.Fr
	mcl.FrAdd(&raAddRb, &ra, &rb)
	mcl.FrNeg(&negRaRb, &raAddRb)

	var rd1AddRd2, negRd1Rd2 mcl.Fr
	mcl.FrAdd(&rd1AddRd2, &rd1, &rd2)
	mcl.FrNeg(&negRd1Rd2, &rd1AddRd2)
	var ehw, ehg, R3 mcl.GT
	mcl.GTPow(&ehw, &cached.hw, &negRaRb)
	mcl.GTPow(&ehg, &cached.hg, &negRd1Rd2)
	mcl.GTMul(&R3, &rxET3g, &ehw)
	mcl.GTMul(&R3, &R3, &ehg)

	var rxT1, R4 mcl.G1
	mcl.G1Mul(&rxT1, &T1, &rx)
	var rd1u mcl.G1
	mcl.G1Mul(&rd1u, &gpk.u, &rd1)
	mcl.G1Sub(&R4, &rxT1, &rd1u)

	var rxT2, R5 mcl.G1
	mcl.G1Mul(&rxT2, &T2, &rx)
	var rd2v mcl.G1
	mcl.G1Mul(&rd2v, &gpk.v, &rd2)
	mcl.G1Sub(&R5, &rxT2, &rd2v)

	cData := append(mData, G1ToBytes(T1)...)
	cData = append(cData, G1ToBytes(T2)...)
	cData = append(cData, G1ToBytes(T3)...)
	cData = append(cData, G1ToBytes(R1)...)
	cData = append(cData, G1ToBytes(R2)...)
	cData = append(cData, GTToBytes(R3)...)
	cData = append(cData, G1ToBytes(R4)...)
	cData = append(cData, G1ToBytes(R5)...)
	c := HashToZp(cData)

	var sa mcl.Fr
	mcl.FrMul(&sa, &c, &alpha)
	mcl.FrAdd(&sa, &sa, &ra)

	var sb mcl.Fr
	mcl.FrMul(&sb, &c, &beta)
	mcl.FrAdd(&sb, &sb, &rb)

	var sx mcl.Fr
	mcl.FrMul(&sx, &c, &gsk.xi)
	mcl.FrAdd(&sx, &sx, &rx)

	var sd1 mcl.Fr
	mcl.FrMul(&sd1, &c, &delta1)
	mcl.FrAdd(&sd1, &sd1, &rd1)

	var sd2 mcl.Fr
	mcl.FrMul(&sd2, &c, &delta2)
	mcl.FrAdd(&sd2, &sd2, &rd2)

	sig := SigmaUi{
		T1:  T1,
		T2:  T2,
		T3:  T3,
		c:   c,
		sa:  sa,
		sb:  sb,
		sx:  sx,
		sd1: sd1,
		sd2: sd2,
	}

	req := AccessRequest{
		MUi:       mData,
		sig:       sig,
		grui:      grui,
		TID:       tid,
		UserID:    userID,
		HomeNCCID: homeNCCID,
		FLEOID:    fleoID,
		Timestamp: ts3,
	}

	return req, rUi
}

func RefVerifyRequestCached(gpk RefGroupPublicKey, req AccessRequest, cached *refPairCache) bool {
	ts3 := req.Timestamp
	if ts3 == 0 && len(req.MUi) >= 10 {
		ts3Str := string(req.MUi[len(req.MUi)-10:])
		parsed, _ := strconv.ParseInt(ts3Str, 10, 64)
		ts3 = parsed
	}
	if !VerifyTimestamp(ts3) {
		fmt.Println("[FLEO] timestamp verification failed")
		return false
	}

	sig := req.sig
	var saU, cT1, R1p mcl.G1
	mcl.G1Mul(&saU, &gpk.u, &sig.sa)
	mcl.G1Mul(&cT1, &sig.T1, &sig.c)
	mcl.G1Sub(&R1p, &saU, &cT1)

	var sbV, cT2, R2p mcl.G1
	mcl.G1Mul(&sbV, &gpk.v, &sig.sb)
	mcl.G1Mul(&cT2, &sig.T2, &sig.c)
	mcl.G1Sub(&R2p, &sbV, &cT2)

	var sxT3 mcl.G1
	mcl.G1Mul(&sxT3, &sig.T3, &sig.sx)
	tmpg2 := gpk.g2
	var e1 mcl.GT
	mcl.Pairing(&e1, &sxT3, &tmpg2)

	var cT3 mcl.G1
	mcl.G1Mul(&cT3, &sig.T3, &sig.c)
	var tmpg2w mcl.G2
	tmpg2w = gpk.w2
	var e2 mcl.GT
	mcl.Pairing(&e2, &cT3, &tmpg2w)

	var saAddSb, negSaSb mcl.Fr
	mcl.FrAdd(&saAddSb, &sig.sa, &sig.sb)
	mcl.FrNeg(&negSaSb, &saAddSb)
	var eHW, e3 mcl.GT
	eHW = cached.hw
	mcl.GTPow(&e3, &eHW, &negSaSb)

	var sd1AddSd2, negSd1Sd2 mcl.Fr
	mcl.FrAdd(&sd1AddSd2, &sig.sd1, &sig.sd2)
	mcl.FrNeg(&negSd1Sd2, &sd1AddSd2)
	var eHg, e4 mcl.GT
	eHg = cached.hg
	mcl.GTPow(&e4, &eHg, &negSd1Sd2)

	var negC mcl.Fr
	mcl.FrNeg(&negC, &sig.c)
	var eGG, e5 mcl.GT
	eGG = cached.gg
	mcl.GTPow(&e5, &eGG, &negC)

	var R3p mcl.GT
	mcl.GTMul(&R3p, &e1, &e2)
	mcl.GTMul(&R3p, &R3p, &e3)
	mcl.GTMul(&R3p, &R3p, &e4)
	mcl.GTMul(&R3p, &R3p, &e5)

	var negSd1 mcl.Fr
	mcl.FrNeg(&negSd1, &sig.sd1)
	var Sd1U, sxT1, R4p mcl.G1
	mcl.G1Mul(&Sd1U, &gpk.u, &negSd1)
	mcl.G1Mul(&sxT1, &sig.T1, &sig.sx)
	mcl.G1Add(&R4p, &Sd1U, &sxT1)

	var negSd2 mcl.Fr
	mcl.FrNeg(&negSd2, &sig.sd2)
	var negSd2V, sxT2, R5p mcl.G1
	mcl.G1Mul(&negSd2V, &gpk.v, &negSd2)
	mcl.G1Mul(&sxT2, &sig.T2, &sig.sx)
	mcl.G1Add(&R5p, &negSd2V, &sxT2)

	cData := append(req.MUi, G1ToBytes(sig.T1)...)
	cData = append(cData, G1ToBytes(sig.T2)...)
	cData = append(cData, G1ToBytes(sig.T3)...)
	cData = append(cData, G1ToBytes(R1p)...)
	cData = append(cData, G1ToBytes(R2p)...)
	cData = append(cData, GTToBytes(R3p)...)
	cData = append(cData, G1ToBytes(R4p)...)
	cData = append(cData, G1ToBytes(R5p)...)
	cPrime := HashToZp(cData)
	if !cPrime.IsEqual(&sig.c) {

		return false
	}

	return true
}

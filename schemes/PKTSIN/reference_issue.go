package main

import (
	"encoding/binary"
	mcl "github.com/alinush/go-mcl"
)

type refLinearProof struct {
	R []G
	Z []Fr
	C Fr
}

func refAttrBytes(a []Fr) []byte {
	var out []byte
	for _, v := range a {
		out = append(out, v.Serialize()...)
	}
	return out
}

func refLinearChallenge(b [][]G, y []G, p refLinearProof, ctx []byte) Fr {
	d := []byte("PKTSIN-APPB-LINEAR")
	for i, row := range b {
		d = append(d, y[i].Serialize()...)
		for _, g := range row {
			d = append(d, g.Serialize()...)
		}
		d = append(d, p.R[i].Serialize()...)
	}
	d = append(d, ctx...)
	return HashToFr(d)
}

func refLinearProve(b [][]G, y []G, w []Fr, ctx []byte) refLinearProof {
	p := refLinearProof{R: make([]G, len(b)), Z: make([]Fr, len(w))}
	a := make([]Fr, len(w))
	for i := range a {
		a[i].Random()
	}
	for i, row := range b {
		for j, g := range row {
			if !g.IsZero() {
				p.R[i] = rgAdd(p.R[i], rgMul(g, a[j]))
			}
		}
	}
	p.C = refLinearChallenge(b, y, p, ctx)
	for i := range a {
		p.Z[i] = rfSub(a[i], rfMul(p.C, w[i]))
	}
	return p
}

func refLinearVerify(b [][]G, y []G, p refLinearProof, ctx []byte) bool {
	c := refLinearChallenge(b, y, p, ctx)
	if !c.IsEqual(&p.C) {
		return false
	}
	for i, row := range b {
		r := rgMul(y[i], c)
		for j, g := range row {
			if !g.IsZero() {
				r = rgAdd(r, rgMul(g, p.Z[j]))
			}
		}
		if !r.IsEqual(&p.R[i]) {
			return false
		}
	}
	return true
}

func RefIssue(pp *PublicParams, uk *UserKey, attr []mcl.Fr, isk *IssuerKey, TP, k uint64) (*Credential, *Dispenser) {
	// 用户步骤：生成承诺 Cm = Y1^{x_u} Y2^{s'}
	var sPrime mcl.Fr
	sPrime.Random()
	// 2. 计算 Cm = Y1^{x_u} + Y2^{s'} (加法群，乘法对应加法)
	var Cm G
	var Y1xu, Y2sp G
	GMul(&Y1xu, &isk.Ipk.Y1, &uk.Usk)
	GMul(&Y2sp, &isk.Ipk.Y2, &sPrime)
	GAdd(&Cm, &Y1xu, &Y2sp)
	// App. B Pi_U^1: shared witnesses for user public key and commitment.
	ub := [][]G{{pp.G0, G{}}, {isk.Ipk.Y1, isk.Ipk.Y2}}
	utarget := []G{uk.Upk, Cm}
	uw := []Fr{uk.Usk, sPrime}
	proofU := refLinearProve(ub, utarget, uw, refAttrBytes(attr))
	if !refLinearVerify(ub, utarget, proofU, refAttrBytes(attr)) {
		panic("PiU1")
	}

	// 签发者步骤：选择 s'', t, U ∈ G
	var sDoublePrime, t mcl.Fr
	sDoublePrime.Random()
	t.Random()
	var U G
	U.Random()

	// 计算 V = g1^{x1} U^{x2 + x3*t} (Cm · Y2^{s''})^{y3} · ũ0^{H1(TP,k) z0} ∏_{i=1~n} ũi^{H1(attr_i) z_i}
	var x2x3t mcl.Fr
	FrMul(&x2x3t, &isk.Isk.Xs[2], &t)
	FrAdd(&x2x3t, &x2x3t, &isk.Isk.Xs[1])

	var Ux2x3t G
	GMul(&Ux2x3t, &U, &x2x3t)

	// 计算 (Cm · Y2^{s''})^{y3}
	var CmY2sp G
	var Y2spd G
	GMul(&Y2spd, &isk.Ipk.Y2, &sDoublePrime)
	GAdd(&CmY2sp, &Cm, &Y2spd)
	var CmY2spY3 G
	GMul(&CmY2spY3, &CmY2sp, &isk.Isk.Ys[2])

	// 计算 ũ0^{H1(TP,k) z0}
	tpBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tpBytes, TP)
	kBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(kBytes, k)
	hTPk := pp.H1(append(tpBytes, kBytes...))
	var u0Htpkz0 G
	var htpkz0 mcl.Fr
	FrMul(&htpkz0, &hTPk, &isk.Isk.Zs[0])
	GMul(&u0Htpkz0, &pp.Utilde[0], &htpkz0)

	// 计算 ∏ ũi^{H1(attr_i) z_i}
	var prodUi G
	prodUi = u0Htpkz0
	for i := 1; i <= pp.N; i++ {
		hAttr := pp.H1(attr[i-1].Serialize())
		var hattrzi mcl.Fr
		FrMul(&hattrzi, &hAttr, &isk.Isk.Zs[i])
		var term G
		GMul(&term, &pp.Utilde[i], &hattrzi)
		GAdd(&prodUi, &prodUi, &term)
	}

	// 组合 V
	var g1x1 G
	GMul(&g1x1, &pp.Gs[1], &isk.Isk.Xs[0])
	var V G
	GAdd(&V, &g1x1, &Ux2x3t)
	GAdd(&V, &V, &CmY2spY3)
	GAdd(&V, &V, &prodUi)
	// App. B Pi_I; include i=0 in Z row to agree with IKeyGen and Verify.
	ib := make([][]G, 3)
	for i := range ib {
		ib[i] = make([]G, pp.N+6)
	}
	ib[0][0] = pp.Gs[1]
	ib[0][4] = pp.Hs[2]
	ib[1][1] = pp.Gs[2]
	ib[1][2] = pp.Gs[3]
	ib[1][3] = rgAdd(pp.Hs[0], pp.Hs[1])
	ib[2][0] = pp.Gs[1]
	ib[2][1] = U
	ib[2][2] = rgMul(U, t)
	ib[2][4] = CmY2sp
	for i := 0; i <= pp.N; i++ {
		ib[1][5+i] = pp.Us[i]
		h := hTPk
		if i > 0 {
			h = pp.H1(attr[i-1].Serialize())
		}
		ib[2][5+i] = rgMul(pp.Utilde[i], h)
	}
	y := rfMul(rfMul(isk.Isk.Ys[0], isk.Isk.Ys[1]), isk.Isk.Ys[2])
	iw := []Fr{isk.Isk.Xs[0], isk.Isk.Xs[1], isk.Isk.Xs[2], y, isk.Isk.Ys[2]}
	iw = append(iw, isk.Isk.Zs...)
	itarget := []G{isk.Ipk.X, rgSub(pp.G0, isk.Ipk.Z), V}
	context := append(sDoublePrime.Serialize(), t.Serialize()...)
	proofI := refLinearProve(ib, itarget, iw, context)
	if !refLinearVerify(ib, itarget, proofI, context) {
		panic("PiI")
	}

	// 用户步骤：计算 s = s' + s''
	var s mcl.Fr
	FrAdd(&s, &sPrime, &sDoublePrime)

	// 生成凭证
	cred := &Credential{
		S:  s,
		T:  t,
		U:  U,
		V:  V,
		TP: TP,
		K:  k,
	}

	// 初始化分配器 D = {1,2,...,k}
	D := &Dispenser{
		Remaining: make([]uint64, k),
	}
	for i := uint64(0); i < k; i++ {
		D.Remaining[i] = i + 1
	}

	return cred, D
}

package main

import (
	"encoding/binary"
	"fmt"
	mcl "github.com/alinush/go-mcl"
)

// App. B transcription; index-zero term and M binding follow main algorithm.
// Not an independent security validation of the source paper.
type RefToken struct {
	*Token
	TIN   G
	Proof refShowProof
}

type refShowProof struct {
	L [7]G
	Z [7]Fr
	C Fr
}

func rgMul(g G, s Fr) G { var o G; GMul(&o, &g, &s); return o }

func rgAdd(a, b G) G { var o G; GAdd(&o, &a, &b); return o }

func rgSub(a, b G) G { var o G; mcl.G1Sub(&o, &a, &b); return o }

func rfSub(a, b Fr) Fr { var o Fr; mcl.FrSub(&o, &a, &b); return o }

func rfMul(a, b Fr) Fr { var o Fr; mcl.FrMul(&o, &a, &b); return o }

func refW(pp *PublicParams, t *Token) Fr {
	var d []byte
	for _, p := range t.Cu {
		d = append(d, p.Serialize()...)
	}
	for _, p := range t.Du {
		d = append(d, p.Serialize()...)
	}
	for _, p := range t.Eu {
		d = append(d, p.Serialize()...)
	}
	return pp.H1(d)
}

func refShowChallenge(pp *PublicParams, t *RefToken, p *refShowProof, a []Fr, msg []byte) Fr {
	d := []byte("PKTSIN-APPB-M-BOUND")
	d = append(d, uint64Bytes(t.Ju)...)
	for _, g := range t.Cu {
		d = append(d, g.Serialize()...)
	}
	for _, g := range t.Du {
		d = append(d, g.Serialize()...)
	}
	for _, g := range t.Eu {
		d = append(d, g.Serialize()...)
	}
	d = append(d, t.Fu.Serialize()...)
	d = append(d, t.TIN.Serialize()...)
	for _, g := range p.L {
		d = append(d, g.Serialize()...)
	}
	for _, f := range a {
		d = append(d, f.Serialize()...)
	}
	d = append(d, uint64Bytes(t.TP)...)
	d = append(d, uint64Bytes(t.K)...)
	d = append(d, msg...)
	return pp.H1(d)
}

func refProveShow(pp *PublicParams, ik *IssuerKey, tok *RefToken, a []Fr, msg []byte, x, s, t, r, w, beta, delta *Fr) refShowProof {
	var p refShowProof
	var masks [7]Fr
	for i := range masks {
		masks[i].Random()
	}
	bs := rgAdd(rgAdd(ik.Ipk.Z, ik.Ipk.Y1), ik.Ipk.Y2)
	p.L[0] = rgAdd(rgMul(pp.G0, *s), rgMul(pp.Hs[0], *r))
	p.L[1] = rgAdd(rgAdd(rgMul(bs, masks[3]), rgMul(pp.Hs[0], masks[0])), rgMul(pp.Hs[1], masks[1]))
	p.L[2] = rgMul(tok.TIN, masks[1])
	alpha1 := FrFromUint64(pp.F(1, tok.TP, tok.Ju))
	base := rgAdd(p.L[0], rgMul(pp.G0, alpha1))
	p.L[3] = rgAdd(rgMul(base, masks[5]), rgMul(pp.Hs[0], masks[6]))
	p.L[4] = rgMul(pp.G0, *w)
	p.L[5] = rgMul(pp.G0, masks[4])
	p.L[6] = rgAdd(rgMul(pp.G0, masks[0]), rgMul(p.L[4], masks[5]))
	p.C = refShowChallenge(pp, tok, &p, a, msg)
	ws := []Fr{*x, *s, *t, *r, *w, *beta, *delta}
	for i := range ws {
		p.Z[i] = rfSub(masks[i], rfMul(p.C, ws[i]))
	}
	return p
}

func refVerifyShow(pp *PublicParams, ik *IssuerKey, t *RefToken, a []Fr, msg []byte) bool {
	p := t.Proof
	ch := refShowChallenge(pp, t, &p, a, msg)
	if !ch.IsEqual(&p.C) {
		return false
	}
	w := refW(pp, t.Token)
	gw := rgMul(pp.G0, w)
	if !gw.IsEqual(&p.L[4]) {
		return false
	}
	bs := rgAdd(rgAdd(ik.Ipk.Z, ik.Ipk.Y1), ik.Ipk.Y2)
	target := rgAdd(rgAdd(t.Du[0], t.Du[1]), t.Cu[3])
	r1 := rgAdd(rgAdd(rgAdd(rgMul(target, p.C), rgMul(bs, p.Z[3])), rgMul(pp.Hs[0], p.Z[0])), rgMul(pp.Hs[1], p.Z[1]))
	if !r1.IsEqual(&p.L[1]) {
		return false
	}
	a0 := FrFromUint64(pp.F(0, t.TP, t.Ju))
	a1 := FrFromUint64(pp.F(1, t.TP, t.Ju))
	r2 := rgAdd(rgMul(rgSub(pp.G0, rgMul(t.TIN, a0)), p.C), rgMul(t.TIN, p.Z[1]))
	if !r2.IsEqual(&p.L[2]) {
		return false
	}
	r3 := rgAdd(rgAdd(rgMul(pp.G0, p.C), rgMul(rgAdd(p.L[0], rgMul(pp.G0, a1)), p.Z[5])), rgMul(pp.Hs[0], p.Z[6]))
	if !r3.IsEqual(&p.L[3]) {
		return false
	}
	r4 := rgAdd(rgMul(p.L[4], p.C), rgMul(pp.G0, p.Z[4]))
	if !r4.IsEqual(&p.L[5]) {
		return false
	}
	r5 := rgAdd(rgAdd(rgMul(t.Fu, p.C), rgMul(pp.G0, p.Z[0])), rgMul(p.L[4], p.Z[5]))
	return r5.IsEqual(&p.L[6])
}

func RefShowWithMessage(pp *PublicParams, uk *UserKey, isk *IssuerKey, cred *Credential, attr []mcl.Fr, Pubattr []mcl.Fr, D *Dispenser, msg []byte) (*RefToken, *G, *Dispenser) {
	// 1. 检查分配器是否为空
	if len(D.Remaining) == 0 {
		return nil, nil, nil
	}

	// 2. 随机选择 J_u
	Ju := D.Remaining[0]
	D.Remaining = D.Remaining[1:]

	// 3. 计算 α0 = f(0, TP, Ju), α1 = f(1, TP, Ju)
	alpha0 := pp.F(0, cred.TP, Ju)
	alpha1 := pp.F(1, cred.TP, Ju)
	alpha0Fr := FrFromUint64(alpha0)
	alpha1Fr := FrFromUint64(alpha1)

	// 4. 选择随机 r ∈ Z_p*
	var r mcl.Fr
	r.Random()

	// 5. 计算 C1 = g0^r V, C2 = g2^r U, C3 = g3^r U^t, C4 = Z^r
	var C1, C2, C3, C4 G
	var g0r, g2r, g3r, Zr, Ut G
	GMul(&g0r, &pp.G0, &r)
	GAdd(&C1, &g0r, &cred.V)

	GMul(&g2r, &pp.Gs[2], &r)
	GAdd(&C2, &g2r, &cred.U)

	GMul(&g3r, &pp.Gs[3], &r)
	GMul(&Ut, &cred.U, &cred.T)
	GAdd(&C3, &g3r, &Ut)

	GMul(&Zr, &isk.Ipk.Z, &r) // 签发者公钥 Z ############
	C4 = Zr

	// 6. 计算 D1 = Y2^r · h1^{x_u}, D2 = Y1^r · h2^s
	var D1, D2 G
	var Y2r, h1xu, Y1r, h2s G
	GMul(&Y2r, &isk.Ipk.Y2, &r) //
	GMul(&h1xu, &pp.Hs[0], &uk.Usk)
	GAdd(&D1, &Y2r, &h1xu)

	GMul(&Y1r, &isk.Ipk.Y1, &r) //
	GMul(&h2s, &pp.Hs[1], &cred.S)
	GAdd(&D2, &Y1r, &h2s)

	// 7. 计算 E0..En
	Eu := make([]G, pp.N+1)
	// E0 = u0^r
	GMul(&Eu[0], &pp.Us[0], &r)

	// 遍历属性
	for i := 1; i <= len(Pubattr); i++ {
		// 公开属性：E_i = u_i^r
		GMul(&Eu[i], &pp.Us[i], &r)
	}

	// 隐藏属性：E_i = u_i^r ũ_i^{H1(attr_i)}
	for i := len(Pubattr) + 1; i <= pp.N; i++ {
		hAttr := pp.H1(attr[i-1].Serialize())
		var uiR, utildeH G
		GMul(&uiR, &pp.Us[i], &r)
		GMul(&utildeH, &pp.Utilde[i], &hAttr)
		GAdd(&Eu[i], &uiR, &utildeH)
	}

	// 8. 计算 w = H1(Cu || Du || Eu)
	cuBytes := append(C1.Serialize(), append(C2.Serialize(), append(C3.Serialize(), C4.Serialize()...)...)...)
	duBytes := append(D1.Serialize(), D2.Serialize()...)
	euBytes := Eu[0].Serialize()
	for i := 1; i <= pp.N; i++ {
		euBytes = append(euBytes, Eu[i].Serialize()...)
	}
	w := pp.H1(append(append(cuBytes, duBytes...), euBytes...))

	// 9. 计算 T_u = g0^{1/(s+α0)}, F_u = Y_u · g0^{w/(s+α1)}
	var salpha0, salpha1 mcl.Fr
	FrAdd(&salpha0, &cred.S, &alpha0Fr)
	FrAdd(&salpha1, &cred.S, &alpha1Fr)

	var invSalpha0, invSalpha1 mcl.Fr
	FrInv(&invSalpha0, &salpha0)
	FrInv(&invSalpha1, &salpha1)

	var Tu G
	GMul(&Tu, &pp.G0, &invSalpha0)

	var wInvSSalpha1 mcl.Fr
	FrMul(&wInvSSalpha1, &w, &invSalpha1)
	var g0wInvSSalpha1 G
	GMul(&g0wInvSSalpha1, &pp.G0, &wInvSSalpha1)
	var Fu G
	GAdd(&Fu, &uk.Upk, &g0wInvSSalpha1)

	// 10. 计算 β = 1/(s+α1), δ = -r·β
	β := invSalpha1
	var δ mcl.Fr
	FrMul(&δ, &r, &β)
	FrNeg(&δ, &δ)
	// Π_U^2 知识证明
	// 11. 生成令牌

	tok := &Token{
		Ju: Ju,
		Cu: [4]G{C1, C2, C3, C4},
		Du: [2]G{D1, D2},
		Eu: Eu,
		Fu: Fu,
		TP: cred.TP,
		K:  cred.K,
	}
	ref := &RefToken{Token: tok, TIN: Tu}
	ref.Proof = refProveShow(pp, isk, ref, Pubattr, msg, &uk.Usk, &cred.S, &cred.T, &r, &w, &β, &δ)
	return ref, &Tu, D
}

func RefVerifyWithMessage(pp *PublicParams, isk *IssuerKey, ref *RefToken, TIN *G, attrD []mcl.Fr, attr []mcl.Fr, msg []byte) bool {
	if ref == nil || TIN == nil || !TIN.IsEqual(&ref.TIN) {
		return false
	}
	tok := ref.Token
	// 1. 检查 TP、Ju 有效性
	if tok.Ju < 1 || tok.Ju > tok.K {
		return false
	}
	// Π_U^2 知识证明
	if !refVerifyShow(pp, isk, ref, attrD, msg) {
		fmt.Println("VerifyPiU2 failed")
		return false
	}

	// 2. 计算 Γ = (E0 · ũ0^{H1(TP,k)})^{z0} · ∏_{attr_i∈ATTR_D} (E_i · ũ_i^{H1(attr_i)})^{z_i} · ∏_{attr_i∉ATTR_D} E_i^{z_i}
	// 简化：直接计算 Γ
	var Γ G
	// E0 · ũ0^{H1(TP,k)}^{z0}
	tpBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tpBytes, tok.TP)
	kBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(kBytes, tok.K)
	hTPk := pp.H1(append(tpBytes, kBytes...))
	var u0Htpk G
	GMul(&u0Htpk, &pp.Utilde[0], &hTPk)
	var E0u0H G
	GAdd(&E0u0H, &tok.Eu[0], &u0Htpk)
	GMul(&Γ, &E0u0H, &isk.Isk.Zs[0])

	// 遍历属性
	for i := 1; i <= len(attrD); i++ {

		// 公开属性：(E_i · ũ_i^{H1(attr_i)})^{z_i}
		hAttr := pp.H1(attrD[i-1].Serialize())
		var uiH G
		GMul(&uiH, &pp.Utilde[i], &hAttr)
		var EiuiH G
		GAdd(&EiuiH, &tok.Eu[i], &uiH)
		var term G
		GMul(&term, &EiuiH, &isk.Isk.Zs[i])
		GAdd(&Γ, &Γ, &term)
	}

	for i := len(attrD) + 1; i <= pp.N; i++ {
		// 隐藏属性：E_i^{z_i}
		var term G
		GMul(&term, &tok.Eu[i], &isk.Isk.Zs[i])
		GAdd(&Γ, &Γ, &term)
	}

	// 3. 验证等式：C1 = g1^{x1} C2^{x2} C3^{x3} C4 · (D1^{y1 y3} D2^{y2 y3}) · Γ
	var left = tok.Cu[0]

	// 计算右边：g1^{x1} C2^{x2} C3^{x3} C4
	var g1x1, C2x2, C3x3, C4 G
	GMul(&g1x1, &pp.Gs[1], &isk.Isk.Xs[0])
	GMul(&C2x2, &tok.Cu[1], &isk.Isk.Xs[1])
	GMul(&C3x3, &tok.Cu[2], &isk.Isk.Xs[2])
	C4 = tok.Cu[3]

	var right G
	GAdd(&right, &g1x1, &C2x2)
	GAdd(&right, &right, &C3x3)
	GAdd(&right, &right, &C4)

	// 计算 (D1^{y1 y3} D2^{y2 y3})
	var y1y3, y2y3 mcl.Fr
	FrMul(&y1y3, &isk.Isk.Ys[0], &isk.Isk.Ys[2])
	FrMul(&y2y3, &isk.Isk.Ys[1], &isk.Isk.Ys[2])
	var D1y1y3, D2y2y3 G
	GMul(&D1y1y3, &tok.Du[0], &y1y3)
	GMul(&D2y2y3, &tok.Du[1], &y2y3)
	GAdd(&right, &right, &D1y1y3)
	GAdd(&right, &right, &D2y2y3)

	// 加上 Γ
	GAdd(&right, &right, &Γ)

	// 比较左右
	return left.IsEqual(&right)
}

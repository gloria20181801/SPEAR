package main

import (
	"encoding/binary"
	"fmt"
	mcl "github.com/alinush/go-mcl"
)

// =====================================================================
// 🔑 1. Setup
// =====================================================================
func Setup(n int) *PublicParams {
	pp := &PublicParams{N: n}
	pp.G.Random()
	pp.G0 = pp.G

	for i := 1; i < 4; i++ {
		pp.Gs[i].Random()
	}
	pp.Gs[0] = pp.G0

	for i := 0; i < 3; i++ {
		pp.Hs[i].Random()
	}

	pp.Us = make([]G, n+1)
	pp.Utilde = make([]G, n+1)
	for i := 0; i <= n; i++ {
		pp.Us[i].Random()
		pp.Utilde[i].Random()
	}
	// 5. 设置哈希函数 H1
	pp.H1 = HashToFr

	// 6. 设置编码函数 f
	pp.F = FEncode
	return pp
}

// =====================================================================
// 🔑 2. IKeyGen
// =====================================================================
func IKeyGen(pp *PublicParams) *IssuerKey {

	ik := &IssuerKey{}
	for i := 0; i < 3; i++ {
		ik.Isk.Xs[i].Random()
		ik.Isk.Ys[i].Random()
	}

	ik.Isk.Zs = make([]Fr, pp.N+1)
	for i := 0; i <= pp.N; i++ {
		ik.Isk.Zs[i].Random()
	}

	if len(pp.Us) != len(ik.Isk.Zs) {
		panic("pp.Us length mismatch with ik.Isk.Zs")
	}
	var tmpx G
	GMul(&tmpx, &pp.Hs[2], &ik.Isk.Ys[2])
	GMul(&ik.Ipk.X, &pp.Gs[1], &ik.Isk.Xs[0])
	GAdd(&ik.Ipk.X, &ik.Ipk.X, &tmpx)

	GMul(&ik.Ipk.Y1, &pp.Hs[0], &ik.Isk.Ys[0])
	GMul(&ik.Ipk.Y2, &pp.Hs[1], &ik.Isk.Ys[1])

	// 实现公式 Z = g0 / (g2^x2 * g3^x3 * (h1*h2)^(y1y2y3) * ∏u_i^z_i)
	// 输入：
	//   g0, g2, g3, h1, h2: G1群元素
	//   x2, x3, v1, v2, v3: Fr标量
	//   u: u_i数组（G1群元素）
	//   z: z_i数组（Fr标量，长度需与u一致）
	// 输出：Z（G1群元素）
	// 2. 计算分母部分 D = g2^x2 * g3^x3 * (h1*h2)^(y1y2y3) * ∏u_i^z_i
	var D G
	// 2.1 计算 g2^x2 * g3^x3
	var g2x2, g3x3 G
	GMul(&g2x2, &pp.Gs[2], &ik.Isk.Xs[1])
	GMul(&g3x3, &pp.Gs[3], &ik.Isk.Xs[2])
	GAdd(&D, &g2x2, &g3x3)

	// 2.2 计算 (h1 * h2) ^(v1*v2*v3)
	var h1h2 G
	var vProd Fr
	GAdd(&h1h2, &pp.Hs[0], &pp.Hs[1]) // h1*h2 = h1 + h2
	FrMul(&vProd, &ik.Isk.Ys[0], &ik.Isk.Ys[1])
	FrMul(&vProd, &vProd, &ik.Isk.Ys[2]) // v1*v2*v3
	var hTerm G
	GMul(&hTerm, &h1h2, &vProd)
	GAdd(&D, &D, &hTerm)

	// 2.3 计算 ∏u_i^z_i = ∑ z_i * u_i
	var uTerm G
	for i := 0; i < len(pp.Us); i++ {
		var uiZi G
		GMul(&uiZi, &pp.Us[i], &ik.Isk.Zs[i])
		GAdd(&uTerm, &uTerm, &uiZi)
	}
	GAdd(&D, &D, &uTerm)

	// 3. 计算 D^{-1} = -D（加法逆元）
	var DNeg mcl.G1
	mcl.G1Neg(&DNeg, &D)

	// 4. 计算 Z = g0 * D^{-1} = g0 + (-D)
	var Z mcl.G1
	mcl.G1Add(&Z, &pp.G0, &DNeg)

	ik.Ipk.Z = Z
	return ik
}

// =====================================================================
// 🔑 3. UKeyGen
// =====================================================================
func UKeyGen(pp *PublicParams, id string) *UserKey {
	uk := &UserKey{ID: id}
	uk.Usk.Random()
	GMul(&uk.Upk, &pp.G0, &uk.Usk)
	return uk
}

// =====================================================================
// 🔑 4. Issue，交互式，此处简化为顺序执行
// =====================================================================
func Issue(pp *PublicParams, uk *UserKey, attr []mcl.Fr, isk *IssuerKey, TP, k uint64) (*Credential, *Dispenser) {
	// 用户步骤：生成承诺 Cm = Y1^{x_u} Y2^{s'}
	var sPrime mcl.Fr
	sPrime.Random()
	// 2. 计算 Cm = Y1^{x_u} + Y2^{s'} (加法群，乘法对应加法)
	var Cm G
	var Y1xu, Y2sp G
	GMul(&Y1xu, &isk.Ipk.Y1, &uk.Usk)
	GMul(&Y2sp, &isk.Ipk.Y2, &sPrime)
	GAdd(&Cm, &Y1xu, &Y2sp)
	//  省略了 Π_U^1 知识证明，直接进入签发者步骤

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
	// 省略了 Π_I^1 知识证明与验证，直接生成凭证 ###################
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

// Verify(isk, tok, TIN, ATTR_D, M) → 0/1
func Verify(pp *PublicParams, isk *IssuerKey, tok *Token, TIN *G, attrD []mcl.Fr, attr []mcl.Fr) bool {
	return VerifyWithMessage(pp, isk, tok, TIN, attrD, attr, nil)
}

func VerifyWithMessage(pp *PublicParams, isk *IssuerKey, tok *Token, TIN *G, attrD []mcl.Fr, attr []mcl.Fr, msg []byte) bool {
	// 1. 检查 TP、Ju 有效性
	if tok.Ju < 1 || tok.Ju > tok.K {
		return false
	}
	// Π_U^2 知识证明
	if !VerifyPiU2(&tok.PiU2, &pp.G0, &pp.Hs[0], &pp.Hs[1], &isk.Ipk.Z, &isk.Ipk.Y1, &isk.Ipk.Y2, &tok.Fu, msg) {
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
		hAttr := pp.H1(attr[i-1].Serialize())
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

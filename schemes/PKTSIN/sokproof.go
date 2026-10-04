package main

import (
	"fmt"
	mcl "github.com/alinush/go-mcl"
)

// VerifyPiU2
// 验证4个等式
func VerifyPiU2(
	pi *PiU2,
	g0, h1, h2, Z, Y1, Y2, F_u *mcl.G1,
	msg []byte,
) bool {

	// 关系1: T_u = g0^{s+α0}
	var negC mcl.Fr
	mcl.FrNeg(&negC, &pi.C)

	// ====================
	// 等式1: g0^s1 * T_u^c == R1
	// ====================
	var g0s1, Tuc, eqa1 mcl.G1
	mcl.G1Mul(&g0s1, g0, &pi.S1)
	mcl.G1Mul(&Tuc, &pi.O1, &pi.C) // tU就o1
	mcl.G1Add(&eqa1, &g0s1, &Tuc)
	if !eqa1.IsEqual(&pi.R1) {
		fmt.Println("VerifyPiU2: equation 1 failed")
		return false
	}

	// ====================
	// 等式2: (g0^s h1^r g0^α1)^s2 * h1^s3 * (g0^s h1^r g0^α1)^cβ h1^cδ == R2
	// ====================
	var g0s, h1r, eqa2 mcl.G1
	mcl.G1Mul(&g0s, &pi.term2, &pi.S2)
	mcl.G1Mul(&h1r, h1, &pi.S3)
	mcl.G1Add(&eqa2, &g0s, &h1r)

	var o2c mcl.G1
	mcl.G1Mul(&o2c, &pi.O2, &pi.C)
	mcl.G1Add(&eqa2, &eqa2, &o2c)

	if !eqa2.IsEqual(&pi.R2) {
		fmt.Println("VerifyPiU2: equation 2 failed")
		return false
	}

	// ====================
	// 等式3: XY1Y2^s4 h1^s5 h2^s6 O3^c == R3
	// ====================
	var sum, h1s5, h2s6, o3c, eqa3 mcl.G1
	mcl.G1Add(&sum, Z, Y1)
	mcl.G1Add(&sum, &sum, Y2)
	mcl.G1Mul(&sum, &sum, &pi.S4)
	mcl.G1Mul(&h1s5, h1, &pi.S5)
	mcl.G1Mul(&h2s6, h2, &pi.S6)
	mcl.G1Add(&eqa3, &sum, &h1s5)
	mcl.G1Add(&eqa3, &eqa3, &h2s6)

	mcl.G1Mul(&o3c, &pi.O3, &pi.C)
	mcl.G1Add(&eqa3, &eqa3, &o3c)

	if !eqa3.IsEqual(&pi.R3) {
		fmt.Println("VerifyPiU2: equation 3 failed")
		return false
	}

	// ====================
	// 等式4: g0^{s7} F_u^c == R4
	// ====================
	var g0s7, FuC, eqa4 mcl.G1
	mcl.G1Mul(&g0s7, g0, &pi.S7)
	mcl.G1Mul(&FuC, &pi.O4, &pi.C)
	mcl.G1Add(&eqa4, &g0s7, &FuC)

	if !eqa4.IsEqual(&pi.R4) {
		fmt.Println("VerifyPiU2: equation 4 failed")
		return false
	}

	// 重新计算挑战值 C = H(eqa1||eqa2||eqa3||eqa4||msg)
	cData := make([]byte, 0)
	cData = append(cData, eqa1.Serialize()...)
	cData = append(cData, eqa2.Serialize()...)
	cData = append(cData, eqa3.Serialize()...)
	cData = append(cData, eqa4.Serialize()...)
	cData = append(cData, msg...)
	Cprime := HashToFr(cData)
	if !Cprime.IsEqual(&pi.C) {
		fmt.Println("VerifyPiU2: challenge mismatch")
		return false
	}

	// fmt.Println("✅ PiU2 proof verified successfully")
	return true
}

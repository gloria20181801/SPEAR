package main

import (
	mcl "github.com/alinush/go-mcl"
)

// Issue(ik, m_vec) → (Cred, π0)
// 注：π0的完整实现见论文附录D，此处实现核心签名生成  ,
func Issue(ik *IssuingKey, pars *PublicParams, mVec []mcl.Fr) *Credential {
	cred := new(Credential)
	cred.MVec = mVec

	// 1. 计算主签名 σ = g1^{x0 + Σ_{i=1}^4 m_i x_i}^-1
	var sum mcl.Fr
	sum = ik.X[0] // x0
	for i := 1; i <= ATTR_NUM; i++ {
		var term mcl.Fr
		mcl.FrMul(&term, &mVec[i-1], &ik.X[i]) // m_i * x_i
		mcl.FrAdd(&sum, &sum, &term)
	}
	var invSum mcl.Fr
	mcl.FrInv(&invSum, &sum) // (x0 + Σ m_i x_i)^(-1)
	mcl.G1Mul(&cred.Sigma, &pars.G1, &invSum)

	// 2. 计算辅助签名 σ_i = σ^{x_i}, i=0..4
	cred.SigmaI = make([]mcl.G1, ATTR_NUM+1)
	for i := 0; i <= ATTR_NUM; i++ {
		mcl.G1Mul(&cred.SigmaI[i], &cred.Sigma, &ik.X[i])
	}

	return cred
}

// Obtain(pars, m_vec, σ, σ_i, π0) → Cred
// 核心验证逻辑：σ0 * Π_{i=1}^4 σ_i^{m_i} == g1
func Obtain(pars *PublicParams, cred *Credential) bool {
	// 验证步骤1：σ0 * Π_{i=1}^4 σ_i^{m_i} == g1
	var left mcl.G1
	left = cred.SigmaI[0] // σ0
	for i := 1; i <= ATTR_NUM; i++ {
		var term mcl.G1
		mcl.G1Mul(&term, &cred.SigmaI[i], &cred.MVec[i-1]) // σ_i^{m_i}
		mcl.G1Add(&left, &left, &term)
	}

	// 比较是否等于g1
	return left.IsEqual(&pars.G1)
}

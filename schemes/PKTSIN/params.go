package main

import (
	mcl "github.com/alinush/go-mcl"
)

const (
	SECURITY_PARAM = 256
	LK             = 8
	LTP            = 32
)

type G = mcl.G1

type Fr = mcl.Fr

// 公共参数（精简结构）
type PublicParams struct {
	G      G
	G0     G
	Gs     [4]G
	Hs     [3]G
	Us     []G
	Utilde []G
	N      int
	H1     func([]byte) mcl.Fr              // 哈希函数 H1: {0,1}* → Z_p*
	F      func(a byte, b, c uint64) uint64 // 编码函数 f(a,b,c) = (a·2^ltp + b)·2^lk + c
}

// 签发密钥
type IssuerKey struct {
	Ipk struct {
		X, Y1, Y2, Z G
	}
	Isk struct {
		Xs [3]Fr
		Ys [3]Fr
		Zs []Fr
	}
}

// 用户密钥
type UserKey struct {
	Upk G
	Usk Fr
	ID  string
}

// 最终匿名凭证 cred_{TP,k}
type Credential struct {
	S  mcl.Fr // s = s' + s''
	T  mcl.Fr // t
	U  mcl.G1 // U
	V  mcl.G1 // V
	TP uint64 // 时间周期
	K  uint64 // 最大认证次数 k
}

// 分配器
type Dispenser struct {
	Remaining []uint64
}

// ==============================
// Π_U² 证明结构 (严格对应图1 SoK)
// ==============================
type PiU2 struct {
	O1, O2, term2, O3, O4 mcl.G1
	R1, R2, R3, R4        mcl.G1
	C                     mcl.Fr
	S1, S2, S3            mcl.Fr // 关系3
	S4, S5, S6            mcl.Fr
	S7                    mcl.Fr // 关系4
}

// 认证令牌
type Token struct {
	Ju   uint64
	TP   uint64
	K    uint64
	Cu   [4]G // C1,C2,C3,C4
	Du   [2]G // D1,D2
	Eu   []G  // E0..En
	Fu   G    // E0..En
	PiU2 PiU2 // ✅ 完整 SoK 证明
}

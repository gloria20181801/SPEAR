package main

import (
	"crypto/sha256"
	mcl "github.com/alinush/go-mcl"
)

// HashToFr 单次哈希，无内存拷贝
func HashToFr(data []byte) mcl.Fr {
	h := sha256.Sum256(data)
	var f mcl.Fr
	// f.SetHashOf(h[:])
	f.SetBigEndianMod(h[:])
	return f
}

// FEncode 论文编码函数 f(a,b,c)
func FEncode(a byte, b, c uint64) uint64 {
	return ((uint64(a)<<LTP)+b)<<LK | c
}

// 群运算：全部复用输出变量，无临时分配
func GAdd(out, x, y *mcl.G1) { mcl.G1Add(out, x, y) }

func GMul(out, x *mcl.G1, y *mcl.Fr) { mcl.G1Mul(out, x, y) }

func FrAdd(out, x, y *mcl.Fr) { mcl.FrAdd(out, x, y) }

func FrMul(out, x, y *mcl.Fr) { mcl.FrMul(out, x, y) }

func FrInv(out, x *mcl.Fr) { mcl.FrInv(out, x) }

func FrNeg(out, x *mcl.Fr) { mcl.FrNeg(out, x) }

func FrSub(out, x, y *mcl.Fr) { mcl.FrSub(out, x, y) }

func FrFromUint64(v uint64) mcl.Fr {
	var f mcl.Fr
	f.SetInt64(int64(v))
	return f
}

// SerializeG 预分配长度，无拷贝
func SerializeG(g *mcl.G1) []byte {
	b := make([]byte, 48) // BLS12-381 固定长度
	b = g.Serialize()
	return b
}

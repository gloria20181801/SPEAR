package main

import (
	"crypto/sha256"
	mcl "github.com/alinush/go-mcl"
	"time"
)

// 全局椭圆曲线参数（使用BLS12_381曲线，适配go-mcl）
var (
	G1 mcl.G1
	G2 mcl.G2
	GT mcl.GT
	Zp mcl.Fr
)

// 生成Z_p^*中的随机数（p为BN254的阶）
func RandomZpStar() mcl.Fr {
	var r mcl.Fr
	// r.SetByCSPRNG()
	r.Random()
	return r
}

// 哈希函数 H: {0,1}^* → Z_p^*
func HashToZp(data []byte) mcl.Fr {
	hash := sha256.Sum256(data)
	var fr mcl.Fr
	fr.SetBigEndianMod(hash[:])
	return fr
}

// 字节序列化工具
func G1ToBytes(g mcl.G1) []byte {
	return g.Serialize()
}

func GTToBytes(g mcl.GT) []byte {
	return g.Serialize()
}

// 时间戳生成（模拟）
func GenTimestamp() int64 {
	ts := time.Now().Unix()
	return ts
}

// 验证时间戳有效性（允许5分钟内的请求）
func VerifyTimestamp(ts int64) bool {
	now := time.Now().Unix()
	return now-ts < 300 && now >= ts
}

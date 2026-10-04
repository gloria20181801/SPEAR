package main

import (
	"crypto/sha256"
	mcl "github.com/alinush/go-mcl"
)

// HashToFr 将输入字节数组哈希到Fr域
func HashToFr(data []byte) mcl.Fr {
	h := sha256.Sum256(data)
	var f mcl.Fr
	// f.SetHashOf(h[:])
	f.SetLittleEndianMod(h[:])
	return f
}

package main

import (
	mcl "github.com/alinush/go-mcl"
)

type GroupMasterKey struct {
	xi1 mcl.Fr
	xi2 mcl.Fr
}

type UserPrivateKey struct {
	Ai mcl.G1
	xi mcl.Fr
}

type UserIndex struct {
	ID  string
	xi  mcl.Fr
	Ai  mcl.G1
	pkL string
	pkG string
	idN string
}

package main

import (
	mcl "github.com/alinush/go-mcl"
)

type AccessRequest struct {
	MUi       []byte
	sig       SigmaUi
	grui      mcl.G1
	TID       string
	UserID    string
	HomeNCCID string
	FLEOID    string
	Timestamp int64
}

type SigmaUi struct {
	T1  mcl.G1
	T2  mcl.G1
	T3  mcl.G1
	c   mcl.Fr
	sa  mcl.Fr
	sb  mcl.Fr
	sx  mcl.Fr
	sd1 mcl.Fr
	sd2 mcl.Fr
}

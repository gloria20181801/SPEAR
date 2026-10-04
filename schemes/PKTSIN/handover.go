package main

import (
	"crypto/sha256"
	"encoding/binary"
)

type PkTSINSession struct {
	LEO       *LEO
	GS        *GS
	GSID      string
	Ru        G
	RuSecret  Fr
	Rgs       G
	RgsSecret Fr
	TP        uint64
	Ju        uint64
	SID       []byte
	SSK       []byte
	EKLU      []byte
	EKLG      []byte
}

func deriveUserGSKey(gsPk, rgs *G, ru *Fr) []byte {
	var staticSecret G
	var ephSecret G
	GMul(&staticSecret, gsPk, ru)
	GMul(&ephSecret, rgs, ru)
	return hashBytes([]byte("H2-SU-GS"), SerializeG(&staticSecret), SerializeG(&ephSecret))
}

func deriveGSUserKey(ruPub *G, gsSk, rgs *Fr) []byte {
	var staticSecret G
	var ephSecret G
	GMul(&staticSecret, ruPub, gsSk)
	GMul(&ephSecret, ruPub, rgs)
	return hashBytes([]byte("H2-SU-GS"), SerializeG(&staticSecret), SerializeG(&ephSecret))
}

func deriveLinkKeyFromPK(pk *G, sk *Fr) []byte {
	var sec G
	GMul(&sec, pk, sk)
	return hashBytes([]byte("H2-LINK"), SerializeG(&sec))
}

func deriveSID(ssk []byte, tp, ju uint64) []byte {
	return hashBytes([]byte("H3-SID"), ssk, uint64Bytes(tp), uint64Bytes(ju))
}

func deriveHandoverSID(prevSID, ssk []byte, tp, ju uint64) []byte {
	return hashBytes([]byte("H3-HANDOVER-SID"), prevSID, ssk, uint64Bytes(tp), uint64Bytes(ju))
}

func hashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func uint64Bytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

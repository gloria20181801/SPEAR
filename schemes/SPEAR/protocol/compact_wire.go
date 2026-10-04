package spear

import (
	"bytes"
	"github.com/alinush/go-mcl"
)

func compactOmitted(i int) bool {
	return i == 8 || i == 9 || i == 10 || i == 12 || (i >= 21 && i <= 25)
}

// The only public completion method returns the final 1234-byte compact message.
func (h *SPEARFullToken) Finish(digest *mcl.G1, nonce []byte) ([]byte, error) {
	w, e := h.finishExpanded(digest, nonce)
	if e != nil {
		return nil, e
	}
	fields, e := splitLengthPrefixed(w, 34)
	if e != nil {
		return nil, e
	}
	out := [][]byte{[]byte("SPEAR-A-WIRE-4"), fields[1]}
	for i := 0; i < 32; i++ {
		if !compactOmitted(i) {
			out = append(out, fields[i+2])
		}
	}
	return appendBytes(out...), nil
}
func unmarshalSPEARCompact(data []byte) (*SPEARAccessMessage, error) {
	fields, e := splitLengthPrefixed(data, 25)
	if e != nil || !bytes.Equal(fields[0], []byte("SPEAR-A-WIRE-4")) || len(fields[1]) != 32 {
		return nil, ErrInvalidRequest
	}
	m := &SPEARAccessMessage{RSat: append([]byte(nil), fields[1]...)}
	m.Proof.TNM.ZKProof = newSingleZKNonMemProof()
	at := 2
	for i, v := range spearWireElements(m) {
		if compactOmitted(i) {
			continue
		}
		if len(fields[at]) != len(v.Serialize()) || receiverDeserialize(v, fields[at]) != nil || !bytes.Equal(fields[at], v.Serialize()) {
			return nil, ErrInvalidRequest
		}
		at++
	}
	if m.HPrime.IsZero() {
		return nil, ErrInvalidRequest
	}
	m.Proof.TNM.ZKProof.SR = m.Proof.ZNM.ZPedersen
	m.Proof.compact = true
	m.Proof.TNM.ZKProof.reconstruct = true
	return m, nil
}

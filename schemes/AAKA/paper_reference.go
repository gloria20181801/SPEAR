package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	mcl "github.com/alinush/go-mcl"
)

var errPaper = errors.New("AAKA reference invalid input")

type paperSN struct {
	enc  *ecdh.PrivateKey
	sign ed25519.PrivateKey
}

type paperUE struct {
	u     *ecdh.PrivateKey
	alpha [32]byte
}

type paperServerSession struct {
	key  []byte
	beta [32]byte
}

func newPaperSN() *paperSN {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		panic(e)
	}
	_, s, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		panic(e)
	}
	return &paperSN{k, s}
}

func x963(z, info []byte, n int) []byte {
	out := []byte{}
	for i := uint32(1); len(out) < n; i++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], i)
		h := sha256.New()
		h.Write(z)
		h.Write(c[:])
		h.Write(info)
		out = append(out, h.Sum(nil)...)
	}
	return out[:n]
}

func ctr(key, iv, data []byte) []byte {
	b, e := aes.NewCipher(key)
	if e != nil {
		panic(e)
	}
	out := make([]byte, len(data))
	cipher.NewCTR(b, iv).XORKeyStream(out, data)
	return out
}

func mac(key, data []byte) []byte { h := hmac.New(sha256.New, key); h.Write(data); return h.Sum(nil) }

func paperReq(sn *paperSN) ([]byte, *paperUE, error) {
	u, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	s := &paperUE{u: u}
	if _, e = rand.Read(s.alpha[:]); e != nil {
		return nil, nil, e
	}
	z, e := u.ECDH(sn.enc.PublicKey())
	if e != nil {
		return nil, nil, e
	}
	pub := u.PublicKey().Bytes()
	keys := x963(z, pub, 64)
	plain := append(append([]byte{}, pub...), s.alpha[:]...)
	ct := ctr(keys[:16], keys[16:32], plain)
	wire := append(append(append([]byte{}, pub...), ct...), mac(keys[32:], ct)[:8]...)
	return wire, s, nil
}

func paperRes(sn *paperSN, req []byte) ([]byte, *paperServerSession, error) {
	if len(req) != 104 {
		return nil, nil, errPaper
	}
	ep, e := ecdh.X25519().NewPublicKey(req[:32])
	if e != nil {
		return nil, nil, e
	}
	z, e := sn.enc.ECDH(ep)
	if e != nil {
		return nil, nil, e
	}
	k := x963(z, req[:32], 64)
	if !hmac.Equal(mac(k[32:], req[32:96])[:8], req[96:]) {
		return nil, nil, errPaper
	}
	plain := ctr(k[:16], k[16:32], req[32:96])
	u, e := ecdh.X25519().NewPublicKey(plain[:32])
	if e != nil {
		return nil, nil, e
	}
	v, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	shared, e := v.ECDH(u)
	if e != nil {
		return nil, nil, e
	}
	st := &paperServerSession{key: x963(shared, []byte("AAKA-session"), 48)}
	rand.Read(st.beta[:])
	msg := append(append(append([]byte{}, v.PublicKey().Bytes()...), plain[32:]...), st.beta[:]...)
	h := sha256.Sum256(msg)
	return append(msg, ed25519.Sign(sn.sign, h[:])...), st, nil
}

func paperSNAuth(sn *paperSN, u *paperUE, res []byte) ([]byte, [32]byte, error) {
	var beta [32]byte
	if len(res) != 160 || !bytes.Equal(u.alpha[:], res[32:64]) {
		return nil, beta, errPaper
	}
	h := sha256.Sum256(res[:96])
	if !ed25519.Verify(sn.sign.Public().(ed25519.PublicKey), h[:], res[96:]) {
		return nil, beta, errPaper
	}
	v, e := ecdh.X25519().NewPublicKey(res[:32])
	if e != nil {
		return nil, beta, e
	}
	z, e := u.u.ECDH(v)
	if e != nil {
		return nil, beta, e
	}
	copy(beta[:], res[64:96])
	return x963(z, []byte("AAKA-session"), 48), beta, nil
}

func paperSeal(key, plain []byte) []byte {
	iv := make([]byte, 16)
	rand.Read(iv)
	out := append(iv, ctr(key[:16], iv, plain)...)
	return append(out, mac(key[16:], out)...)
}

func paperOpen(key, wire []byte) ([]byte, error) {
	if len(wire) < 48 {
		return nil, errPaper
	}
	n := len(wire) - 32
	if !hmac.Equal(mac(key[16:], wire[:n]), wire[n:]) {
		return nil, errPaper
	}
	return ctr(key[:16], wire[:16], wire[16:n]), nil
}

func paperPresent(p *PublicParams, cr *Credential, beta [32]byte) *Presentation {
	q := new(Presentation)
	var r mcl.Fr
	for r.IsZero() {
		r.Random()
	}
	mcl.G1Mul(&q.SigmaPrime, &cr.Sigma, &r)
	q.SigmaHatI = make([]mcl.G1, 5)
	for i := range q.SigmaHatI {
		mcl.G1Mul(&q.SigmaHatI[i], &cr.SigmaI[i], &r)
	}
	mcl.G1Mul(&q.C1, &p.G1, &r)
	q.SigmaBar = q.C1
	for i := 0; i < 4; i++ {
		var term mcl.G1
		mcl.G1Mul(&term, &q.SigmaHatI[i+1], &cr.MVec[i])
		mcl.G1Sub(&q.SigmaBar, &q.SigmaBar, &term)
	}
	var hr, id mcl.G1
	mcl.G1Mul(&hr, &p.H, &r)
	mcl.G1Mul(&id, &p.G1, &cr.MVec[3])
	mcl.G1Add(&q.C2, &id, &hr)
	q.A = q.SigmaHatI[0]
	for i := 0; i < 3; i++ {
		var term mcl.G1
		mcl.G1Mul(&term, &q.SigmaHatI[i+1], &cr.MVec[i])
		mcl.G1Add(&q.A, &q.A, &term)
	}
	mcl.FrNeg(&q.B, &cr.MVec[3])
	q.Pi.Y1 = q.A
	q.Pi.Y4 = q.C1
	// Appendix D establishes y2=g1^r and y3=h^r; Appendix F transmits both.
	q.Pi.Y2 = q.C1
	q.Pi.Y3 = hr
	var a, b, nb mcl.Fr
	a.Random()
	b.Random()
	mcl.FrNeg(&nb, &b)
	var y1, y2, y3, tmp mcl.G1
	mcl.G1Mul(&y2, &p.G1, &a)
	mcl.G1Mul(&tmp, &q.SigmaHatI[4], &nb)
	mcl.G1Add(&y1, &y2, &tmp)
	mcl.G1Mul(&y3, &p.H, &a)
	q.Pi.C = paperChallenge(y1, y2, y3, beta)
	mcl.FrMul(&q.Pi.A_prime, &q.Pi.C, &r)
	mcl.FrAdd(&q.Pi.A_prime, &q.Pi.A_prime, &a)
	mcl.FrMul(&q.Pi.B_prime, &q.Pi.C, &cr.MVec[3])
	mcl.FrAdd(&q.Pi.B_prime, &q.Pi.B_prime, &b)
	q.MVec = append([]mcl.Fr(nil), cr.MVec[:3]...)
	return q
}

func paperChallenge(y1, y2, y3 mcl.G1, beta [32]byte) mcl.Fr {
	d := append(y1.Serialize(), y2.Serialize()...)
	d = append(d, y3.Serialize()...)
	d = append(d, beta[:]...)
	var c mcl.Fr
	h := sha256.Sum256(d)
	c.SetBigEndianMod(h[:])
	return c
}

func paperVerify(p *PublicParams, q *Presentation, beta [32]byte) bool {
	if len(q.SigmaHatI) != 5 || len(q.MVec) != 3 {
		return false
	}
	// Published Appendix F: y1=A, y4=c1; y2,y3 are carried in pi.
	var nc, nb mcl.Fr
	mcl.FrNeg(&nc, &q.Pi.C)
	mcl.FrNeg(&nb, &q.Pi.B_prime)
	var y1, y2, y3, y4, g, tmp mcl.G1
	mcl.G1Mul(&g, &p.G1, &q.Pi.A_prime)
	mcl.G1Mul(&y1, &q.A, &nc)
	mcl.G1Add(&y1, &y1, &g)
	mcl.G1Mul(&tmp, &q.SigmaHatI[4], &nb)
	mcl.G1Add(&y1, &y1, &tmp)
	mcl.G1Mul(&y2, &q.Pi.Y2, &nc)
	mcl.G1Add(&y2, &y2, &g)
	mcl.G1Mul(&y3, &q.Pi.Y3, &nc)
	mcl.G1Mul(&tmp, &p.H, &q.Pi.A_prime)
	mcl.G1Add(&y3, &y3, &tmp)
	mcl.G1Mul(&y4, &q.C1, &nc)
	mcl.G1Add(&y4, &y4, &g)
	c := paperChallenge(y1, y2, y3, beta)
	if !c.IsEqual(&q.Pi.C) || !y2.IsEqual(&y4) {
		return false
	}
	var left, right mcl.GT
	mcl.Pairing(&left, &q.SigmaBar, &p.G2)
	mcl.Pairing(&right, &q.SigmaPrime, &p.X[0])
	return left.IsEqual(&right)
}

func paperPresBytes(q *Presentation) []byte {
	var out []byte
	for i := range q.MVec {
		out = append(out, q.MVec[i].Serialize()...)
	}
	for _, g := range []mcl.G1{q.SigmaBar, q.SigmaPrime, q.SigmaHatI[0], q.SigmaHatI[1], q.SigmaHatI[2], q.SigmaHatI[3], q.SigmaHatI[4], q.C1, q.C2, q.A} {
		out = append(out, g.Serialize()...)
	}
	for _, s := range []mcl.Fr{q.B, q.Pi.C, q.Pi.A_prime, q.Pi.B_prime} {
		out = append(out, s.Serialize()...)
	}
	out = append(out, q.Pi.Y2.Serialize()...)
	out = append(out, q.Pi.Y3.Serialize()...)
	return out
}

func paperParsePres(data []byte) (*Presentation, error) {
	q := &Presentation{MVec: make([]mcl.Fr, 3), SigmaHatI: make([]mcl.G1, 5)}
	type elem interface {
		Serialize() []byte
		Deserialize([]byte) error
	}
	var elements []elem
	for i := range q.MVec {
		elements = append(elements, &q.MVec[i])
	}
	elements = append(elements, &q.SigmaBar, &q.SigmaPrime, &q.SigmaHatI[0], &q.SigmaHatI[1], &q.SigmaHatI[2], &q.SigmaHatI[3], &q.SigmaHatI[4], &q.C1, &q.C2, &q.A, &q.B, &q.Pi.C, &q.Pi.A_prime, &q.Pi.B_prime, &q.Pi.Y2, &q.Pi.Y3)
	for _, x := range elements {
		n := len(x.Serialize())
		if len(data) < n || x.Deserialize(data[:n]) != nil {
			return nil, errPaper
		}
		data = data[n:]
	}
	if len(data) != 0 {
		return nil, errPaper
	}
	q.Pi.Y1 = q.A
	q.Pi.Y4 = q.C1
	return q, nil
}

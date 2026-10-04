package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	mcl "github.com/alinush/go-mcl"
	"math/big"
	"time"
)

const (
	scalarWireBytes    = 32
	hashWireBytes      = 32
	identityWireBytes  = 32
	eccPointWireBytes  = 48
	timestampWireBytes = 8
	aesGCMOverhead     = 28
)

var g1Base mcl.G1

type GS struct {
	MK           []byte
	RevokedByPID map[string]RevokedUser
	Registered   map[string]RegistrationRecord
}

type RevokedUser struct {
	ID  []byte
	PID []byte
	Pub []byte
}

type LEO struct {
	ID     []byte
	PID    []byte
	M      []byte
	K      []byte
	Public []byte
	SSK    []byte

	Handover map[string]LEOHandoverState
}

type HAP struct {
	ID     []byte
	PID    []byte
	M      []byte
	K      []byte
	Public []byte
}

type EU struct {
	ID       []byte
	Password []byte
	RI       []byte
	RE       []byte

	SHID []byte
	SMi  []byte
	SPID []byte
	Vi   []byte
	NEU  byte

	PID    []byte
	Mi     []byte
	Public []byte

	TK       []byte
	TID2     []byte
	SK       []byte
	ER       []byte
	TargetID []byte
}

type InitialSession struct {
	PIDi   []byte
	PIDLEO []byte
	TK     []byte
	TID2   []byte
	SK     []byte
	RM1    []byte
	PKi    []byte
}

type PreHandoverBundle struct {
	ToLEO2 []byte
	ToEU   []byte
	TS1    []byte
}

type LEOHandoverState struct {
	RS1    []byte
	PIDi   []byte
	TK     []byte
	TID2   []byte
	ER     []byte
	PIDLEO []byte
	TA1    []byte
}

func NewGS() *GS {
	return &GS{
		MK:           randomBytes(32),
		RevokedByPID: make(map[string]RevokedUser),
		Registered:   make(map[string]RegistrationRecord),
	}
}

func RegisterLEO(gs *GS, label string) *LEO {
	id := fixedID(label)
	r := randomBytes(32)
	pid := hash(id, gs.MK)
	m := hash(id, gs.MK, r)
	k := randomBytes(32)
	public := baseMult(hash(k, m))
	return &LEO{
		ID:       id,
		PID:      pid,
		M:        m,
		K:        k,
		Public:   public,
		SSK:      randomBytes(32),
		Handover: make(map[string]LEOHandoverState),
	}
}

func RegisterHAP(gs *GS, label string) *HAP {
	id := fixedID(label)
	r := randomBytes(32)
	pid := hash(id, gs.MK)
	m := hash(id, gs.MK, r)
	k := randomBytes(32)
	public := baseMult(hash(k, m))
	return &HAP{ID: id, PID: pid, M: m, K: k, Public: public}
}

func RegisterEU(gs *GS, idLabel, passwordLabel string) *EU {
	id := fixedID(idLabel)
	pw := fixedID(passwordLabel)
	ri := randomBytes(32)
	re := randomBytes(32)
	hid := hash(id, ri)
	hpw := hash(pw, re)

	rEU := randomBytes(32)
	mi := hash(hpw, rEU, gs.MK)
	pid := hash(rEU, id, gs.MK)
	public := baseMult(hash(pid, mi))

	shid := xorBytes(hid, hash(hpw, re))
	smi := xorBytes(mi, hash(id, hid, re, pw))
	spid := xorBytes(pid, hash(re, mi, hpw))
	si := hash(pid, mi)
	vi := fuzzy(hash(pid, si, hid, hpw, mi), 16)

	gs.Registered[string(pid)] = RegistrationRecord{RID: xorBytes(id, hash(pid, gs.MK, public)), PID: clone(pid), Pub: clone(public)}
	return &EU{
		ID:       id,
		Password: pw,
		RI:       ri,
		RE:       re,
		SHID:     shid,
		SMi:      smi,
		SPID:     spid,
		Vi:       vi,
		NEU:      16,
		PID:      pid,
		Mi:       mi,
		Public:   public,
	}
}

func InitialAuthentication(eu *EU, hap *HAP, leo *LEO) (*InitialSession, bool) {
	hpw := hash(eu.Password, eu.RE)
	hid := xorBytes(eu.SHID, hash(hpw, eu.RE))
	mi := xorBytes(eu.SMi, hash(eu.ID, hid, eu.RE, eu.Password))
	pid := xorBytes(eu.SPID, hash(eu.RE, mi, hpw))
	si := hash(pid, mi)
	vi := fuzzy(hash(pid, si, hid, hpw, mi), eu.NEU)
	if !bytes.Equal(vi, eu.Vi) {
		return nil, false
	}

	rm1 := randomBytes(32)
	tm1 := timestampBytes()
	hapSecret := hash(hap.K, hap.M)
	ehi := scalarMult(hap.Public, si)
	pki := baseMult(rm1)
	ai := scalarMult(hap.Public, rm1)
	tid1 := xorBytes(pid, hash(ai, hap.PID, tm1))
	vm1 := hash(ehi, tm1, hap.PID, pid)

	if !fresh(tm1) {
		return nil, false
	}
	ak := scalarMult(pki, hapSecret)
	pidFromTID := xorBytes(tid1, hash(ak, hap.PID, tm1))
	ehk := scalarMult(eu.Public, hapSecret)
	if !bytes.Equal(vm1, hash(ehk, tm1, hap.PID, pidFromTID)) {
		return nil, false
	}

	tm2 := timestampBytes()
	hlk := scalarMult(leo.Public, hapSecret)
	htid1 := xorBytes(pidFromTID, hash(hlk, tm2))
	vm2 := hash(hap.PID, pidFromTID, tm2)

	if !fresh(tm2) {
		return nil, false
	}
	leoSecret := hash(leo.K, leo.M)
	hlj := scalarMult(hap.Public, leoSecret)
	pidAtLEO := xorBytes(htid1, hash(hlj, tm2))
	if !bytes.Equal(vm2, hash(hap.PID, pidAtLEO, tm2)) {
		return nil, false
	}

	rm2 := randomBytes(32)
	tm3 := timestampBytes()
	pkj := baseMult(rm2)
	lij := scalarMult(pki, rm2)
	tk := hash(lij, pidAtLEO, leo.PID)
	sk := hash(lij, leo.PID, tk, tm3)
	vm3 := hash(sk, tk, lij, tm3)

	if !fresh(tm3) {
		return nil, false
	}
	spm := xorBytes(leo.PID, hash(ehk, tm3, ak))
	vm4 := hash(vm3, leo.PID)

	if !fresh(tm3) {
		return nil, false
	}
	lijEU := scalarMult(pkj, rm1)
	pidLEO := xorBytes(spm, hash(ehi, tm3, ai))
	tkEU := hash(lijEU, pid, pidLEO)
	tid2 := hash(pid, tkEU)
	skEU := hash(lijEU, pidLEO, tkEU, tm3)
	vm4Expected := hash(hash(skEU, tkEU, lijEU, tm3), pidLEO)
	if !bytes.Equal(vm4, vm4Expected) {
		return nil, false
	}

	eu.TK = tkEU
	eu.TID2 = tid2
	eu.SK = skEU
	eu.TargetID = leo.PID
	return &InitialSession{PIDi: pid, PIDLEO: leo.PID, TK: tk, TID2: tid2, SK: sk, RM1: rm1, PKi: pki}, true
}

func PreHandover(source *LEO, target *LEO, eu *EU, s *InitialSession) (*PreHandoverBundle, bool) {
	rs1 := randomBytes(32)
	ts1 := timestampBytes()
	er := hash(target.PID, rs1)
	tid2 := hash(s.PIDi, s.TK)
	vs1 := hash(er, rs1, target.PID, tid2, ts1)
	vs2 := hash(er, target.PID, ts1)

	msgLEOPlain := concat(s.PIDi, rs1, s.TK, vs1)
	msgEUPlain := concat(er, target.PID, vs2)
	toLEO2 := seal(source.SSK, msgLEOPlain, ts1)
	toEU := seal(s.SK, msgEUPlain, ts1)

	if !fresh(ts1) {
		return nil, false
	}
	leoPlain, ok := open(target.SSK, toLEO2, ts1)
	if !ok || len(leoPlain) != 128 {
		return nil, false
	}
	pid := clone(leoPlain[0:32])
	rs := clone(leoPlain[32:64])
	tk := clone(leoPlain[64:96])
	recvVS1 := clone(leoPlain[96:128])
	er2 := hash(target.PID, rs)
	tid := hash(pid, tk)
	if !bytes.Equal(recvVS1, hash(er2, rs, target.PID, tid, ts1)) {
		return nil, false
	}
	target.Handover[string(tid)] = LEOHandoverState{
		RS1:    rs,
		PIDi:   pid,
		TK:     tk,
		TID2:   tid,
		ER:     er2,
		PIDLEO: target.PID,
	}

	if !fresh(ts1) {
		return nil, false
	}
	euPlain, ok := open(eu.SK, toEU, ts1)
	if !ok || len(euPlain) != 96 {
		return nil, false
	}
	euER := clone(euPlain[0:32])
	euPIDLEO2 := clone(euPlain[32:64])
	euVS2 := clone(euPlain[64:96])
	if !bytes.Equal(euVS2, hash(euER, euPIDLEO2, ts1)) {
		return nil, false
	}
	eu.ER = euER
	eu.TargetID = euPIDLEO2
	eu.TID2 = tid
	return &PreHandoverBundle{ToLEO2: toLEO2, ToEU: toEU, TS1: ts1}, true
}

func HandoverAuthentication(eu *EU, leo *LEO) ([]byte, bool) {
	state, ok := leo.Handover[string(eu.TID2)]
	if !ok {
		return nil, false
	}

	ta1 := timestampBytes()
	er := hash(leo.PID, state.RS1)
	tid2 := hash(state.PIDi, state.TK)
	ra1 := xorBytes(state.RS1, hash(er, state.TK, ta1))
	va1 := hash(state.RS1, tid2, state.TK, leo.PID, er, ta1)
	state.TA1 = ta1
	leo.Handover[string(tid2)] = state

	if !fresh(ta1) || !fresh(ta1) {
		return nil, false
	}
	rs1 := xorBytes(ra1, hash(eu.ER, eu.TK, ta1))
	erPrime := hash(eu.TargetID, rs1)
	va1Expected := hash(rs1, eu.TID2, eu.TK, eu.TargetID, erPrime, ta1)
	if !bytes.Equal(va1, va1Expected) || !bytes.Equal(eu.ER, erPrime) {
		return nil, false
	}

	ra := randomBytes(32)
	ta2 := timestampBytes()
	ra2 := xorBytes(ra, hash(eu.TK, ta1, eu.PID, eu.ER))
	skNew := hash(rs1, ra, ta2, eu.TK, eu.TargetID)
	tkNew := hash(eu.TK, ra, eu.PID, eu.TargetID)
	tid3 := hash(eu.PID, tkNew)
	va2 := hash(ra, skNew, tid3, tkNew, ta2)

	if !fresh(ta2) || !fresh(ta2) {
		return nil, false
	}
	raAtLEO := xorBytes(ra2, hash(state.TK, ta1, state.PIDi, state.ER))
	skAtLEO := hash(state.RS1, raAtLEO, ta2, state.TK, leo.PID)
	tkAtLEO := hash(state.TK, raAtLEO, state.PIDi, leo.PID)
	tid3AtLEO := hash(state.PIDi, tkAtLEO)
	va2Expected := hash(raAtLEO, skAtLEO, tid3AtLEO, tkAtLEO, ta2)
	if !bytes.Equal(va2, va2Expected) {
		return nil, false
	}

	eu.SK = skNew
	eu.TK = tkNew
	eu.TID2 = tid3
	delete(leo.Handover, string(tid2))
	leo.Handover[string(tid3)] = LEOHandoverState{
		RS1:    state.RS1,
		PIDi:   state.PIDi,
		TK:     tkAtLEO,
		TID2:   tid3AtLEO,
		ER:     state.ER,
		PIDLEO: leo.PID,
	}
	return skNew, true
}

// REP1/REP2: report PID, retrieve the registered record, and unmask RID.
func RevokeUser(gs *GS, leo *LEO, eu *EU) RevokedUser {
	record, ok := gs.Registered[string(eu.PID)]
	if !ok {
		panic("unknown PID")
	}
	revoked := RevokedUser{ID: xorBytes(record.RID, hash(record.PID, gs.MK, record.Pub)), PID: clone(record.PID), Pub: clone(record.Pub)}
	gs.RevokedByPID[string(record.PID)] = revoked
	return revoked
}

type RegistrationRecord struct{ RID, PID, Pub []byte }

func fuzzy(h []byte, n byte) []byte {
	x := new(big.Int).SetBytes(h)
	x.Mod(x, big.NewInt(int64(n)))
	return []byte{byte(x.Uint64())}
}

func fresh(ts []byte) bool {
	if len(ts) != 8 {
		return false
	}
	then := int64(binary.BigEndian.Uint64(ts))
	d := time.Now().UnixNano() - then
	return d > -int64(5*time.Minute) && d < int64(5*time.Minute)
}

func initialAuthCommBytes() int {
	return (hashWireBytes + eccPointWireBytes + hashWireBytes + timestampWireBytes) +
		(hashWireBytes + identityWireBytes + eccPointWireBytes + hashWireBytes + timestampWireBytes) +
		(eccPointWireBytes + hashWireBytes + timestampWireBytes) +
		(eccPointWireBytes + hashWireBytes + hashWireBytes + timestampWireBytes)
}

func preHandoverCommBytes() int {
	return (4*hashWireBytes + aesGCMOverhead + timestampWireBytes) +
		(3*hashWireBytes + aesGCMOverhead + timestampWireBytes)
}

func handoverLogicalCommBytes() int {
	return (3*hashWireBytes + timestampWireBytes) + (2*hashWireBytes + timestampWireBytes)
}

func handoverRelayedCommBytes() int {
	return 2 * handoverLogicalCommBytes()
}

func hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func randomBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func fixedID(label string) []byte {
	return hash([]byte(label))
}

func timestampBytes() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	return b[:]
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i%len(b)]
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var total int
	for _, part := range parts {
		total += len(part)
	}
	out := make([]byte, 0, total)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func clone(in []byte) []byte {
	return append([]byte(nil), in...)
}

func initCurve() {
	mcl.InitMclHelper(mcl.BLS12_381)
	if err := g1Base.HashAndMapTo([]byte("MEC-STIN-G1-base")); err != nil {
		panic(err)
	}
}

func baseMult(scalar []byte) []byte {
	fr := hashToFr(scalar)
	var out mcl.G1
	mcl.G1Mul(&out, &g1Base, &fr)
	return out.Serialize()
}

func scalarMult(public []byte, scalar []byte) []byte {
	var point mcl.G1
	point.Deserialize(public)
	fr := hashToFr(scalar)
	var out mcl.G1
	mcl.G1Mul(&out, &point, &fr)
	return out.Serialize()
}

func hashToFr(s []byte) mcl.Fr {
	var fr mcl.Fr
	fr.SetBigEndianMod(s)
	return fr
}

func seal(key, plaintext, aad []byte) []byte {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := randomBytes(gcm.NonceSize())
	out := append([]byte(nil), nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)
	return out
}

func open(key, sealed, aad []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, false
	}
	nonce := sealed[:gcm.NonceSize()]
	ciphertext := sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, false
	}
	return plain, true
}

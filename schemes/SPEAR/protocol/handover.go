package spear

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"

	"crypto/rand"
	"sync"
	"time"
)

// Policy fields are authenticated as part of both encrypted and signed cookies.
// Session expiry is fixed at full access and is never extended by handover.
type spearCookieClaims struct {
	Version                               string
	Issuer, TargetGS, TargetSatellite     string
	Token                                 [32]byte
	SID                                   [32]byte
	C1, C2                                []byte
	NotBefore, ExpiresAt, SessionDeadline int64
}

type SPEARHandoverAuthority struct {
	mu             sync.Mutex
	id             string
	signing        ed25519.PrivateKey
	symmetric      []byte
	trusted        map[string]ed25519.PublicKey
	sessions       map[[32]byte]SPEARAccepted
	spent          map[string]int64
	now            func() time.Time
	sealed         uint64
	clockHighWater int64
}

// mu must be held. Retaining a watermark prevents expiry-based replay-record
// cleanup followed by clock rollback from making an old cookie valid again.
func (a *SPEARHandoverAuthority) clockNow() int64 {
	n := a.now().Unix()
	if n < a.clockHighWater {
		return -1
	}
	a.clockHighWater = n
	return n
}

func NewSPEARHandoverAuthority(id string, signing ed25519.PrivateKey, symmetric []byte, trusted map[string]ed25519.PublicKey) (*SPEARHandoverAuthority, error) {
	if id == "" || len(signing) != ed25519.PrivateKeySize || len(symmetric) != 32 {
		return nil, ErrInvalidRequest
	}
	a := &SPEARHandoverAuthority{id: id, signing: append(ed25519.PrivateKey(nil), signing...), symmetric: append([]byte(nil), symmetric...), trusted: map[string]ed25519.PublicKey{}, sessions: map[[32]byte]SPEARAccepted{}, spent: map[string]int64{}, now: time.Now}
	for id, key := range trusted {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalidRequest
		}
		a.trusted[id] = append(ed25519.PublicKey(nil), key...)
	}
	a.trusted[id] = append(ed25519.PublicKey(nil), signing.Public().(ed25519.PublicKey)...)
	return a, nil
}

// Trusted access-acceptance path only. The caller must persist this record before
// business acceptance; never populate it directly from an unauthenticated UE.
func (a *SPEARHandoverAuthority) Register(r SPEARAccepted) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.register(r)
}

func (a *SPEARHandoverAuthority) register(r SPEARAccepted) error {
	now := a.clockNow()
	if now < 0 || r.SID == [32]byte{} || r.Deadline <= now || !r.C1.IsValid() || !r.C1.IsValidOrder() || !r.C2.IsValid() || !r.C2.IsValidOrder() {
		return ErrInvalidRequest
	}
	if old, ok := a.sessions[r.SID]; ok && SPEARAuditFingerprint(old) != SPEARAuditFingerprint(r) {
		return ErrInvalidRequest
	}
	a.sessions[r.SID] = r
	return nil
}

// Invoke only for a SID owned by the authenticated source channel. Ciphertext
// and deadline come from the accepted record, never from a cookie request.
func (a *SPEARHandoverAuthority) Issue(sid [32]byte, targetGS, targetSatellite string, ttl time.Duration, signed bool) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clockNow()
	r, ok := a.sessions[sid]
	if now < 0 || !ok || now >= r.Deadline || targetGS == "" || targetSatellite == "" || ttl < time.Second || ttl > 5*time.Minute || (!signed && targetGS != a.id) {
		return nil, ErrInvalidRequest
	}
	expiry := now + int64(ttl/time.Second)
	if expiry > r.Deadline {
		expiry = r.Deadline
	}
	c := spearCookieClaims{Version: "SPEAR-A-COOKIE-2", Issuer: a.id, TargetGS: targetGS, TargetSatellite: targetSatellite, SID: sid, C1: r.C1.Serialize(), C2: r.C2.Serialize(), NotBefore: now, ExpiresAt: expiry, SessionDeadline: r.Deadline}
	if _, err := rand.Read(c.Token[:]); err != nil {
		return nil, err
	}
	payload, err := encodeSPEARCookie(c)
	if err != nil {
		return nil, err
	}
	if signed {
		sig := ed25519.Sign(a.signing, appendBytes([]byte("SPEAR-A-SIGNED-COOKIE-1"), payload))
		return appendBytes([]byte("signed"), []byte(a.id), payload, sig), nil
	}
	// Random 96-bit GCM IV: cap calls per encryption key; do not reset with same key.
	if a.sealed >= 1<<24 {
		return nil, ErrInvalidRequest
	}
	a.sealed++
	ciphertext, err := Encrypt(a.symmetric, payload)
	if err != nil {
		return nil, err
	}
	return appendBytes([]byte("sealed"), []byte(a.id), ciphertext), nil
}

// Call at the GS, for the satellite identity authenticated by the backhaul.
// It consumes before returning success, so business release must follow success.
func (a *SPEARHandoverAuthority) Consume(cookie []byte, targetSatellite string) (*SPEARAccepted, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(cookie) > 4096 || targetSatellite == "" {
		return nil, ErrInvalidRequest
	}
	fields, err := splitLengthPrefixed(cookie, 4)
	var payload []byte
	if err == nil && string(fields[0]) == "signed" {
		key := a.trusted[string(fields[1])]
		if Verify(key, appendBytes([]byte("SPEAR-A-SIGNED-COOKIE-1"), fields[2]), fields[3]) != nil {
			return nil, ErrInvalidRequest
		}
		payload = fields[2]
	} else {
		fields, err = splitLengthPrefixed(cookie, 3)
		if err != nil || string(fields[0]) != "sealed" || string(fields[1]) != a.id {
			return nil, ErrInvalidRequest
		}
		payload, err = Decrypt(a.symmetric, fields[2])
		if err != nil {
			return nil, ErrInvalidRequest
		}
	}
	c, err := decodeSPEARCookie(payload)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	now := a.clockNow()
	if now < 0 || c.Version != "SPEAR-A-COOKIE-2" || c.Issuer != string(fields[1]) || c.TargetGS != a.id || c.TargetSatellite != targetSatellite || c.Token == [32]byte{} || now < c.NotBefore || now >= c.ExpiresAt || c.ExpiresAt > c.SessionDeadline || c.NotBefore >= c.ExpiresAt {
		return nil, ErrInvalidRequest
	}
	replayKey := string(appendBytes([]byte(c.Issuer), c.Token[:]))
	for k, expiry := range a.spent {
		if now >= expiry {
			delete(a.spent, k)
		}
	}
	if _, used := a.spent[replayKey]; used {
		return nil, ErrInvalidRequest
	}
	// Authenticated cookies for an already registered immutable session do not
	// introduce new points. Match their exact encodings and fixed deadline.
	if old, ok := a.sessions[c.SID]; ok {
		if old.Deadline != c.SessionDeadline || now >= old.Deadline ||
			!bytes.Equal(old.C1.Serialize(), c.C1) || !bytes.Equal(old.C2.Serialize(), c.C2) {
			return nil, ErrInvalidRequest
		}
		finalNow := a.clockNow()
		if finalNow < 0 || finalNow >= c.ExpiresAt || finalNow >= old.Deadline {
			return nil, ErrInvalidRequest
		}
		a.spent[replayKey] = c.ExpiresAt
		return &old, nil
	}
	r := SPEARAccepted{SID: c.SID, Deadline: c.SessionDeadline}
	if len(c.C1) != len(r.C1.Serialize()) || len(c.C2) != len(r.C2.Serialize()) {
		return nil, ErrInvalidRequest
	}
	if r.C1.Deserialize(c.C1) != nil || r.C2.Deserialize(c.C2) != nil || !bytes.Equal(r.C1.Serialize(), c.C1) || !bytes.Equal(r.C2.Serialize(), c.C2) {
		return nil, ErrInvalidRequest
	}
	if a.register(r) != nil {
		return nil, ErrInvalidRequest
	}
	a.spent[replayKey] = c.ExpiresAt
	return &r, nil
}

// Canonical binary encoding for the final handover cookie.
func encodeSPEARCookie(c spearCookieClaims) ([]byte, error) {
	if c.Version != "SPEAR-A-COOKIE-2" || len(c.Issuer) > 128 || len(c.TargetGS) > 128 || len(c.TargetSatellite) > 128 {
		return nil, ErrInvalidRequest
	}
	return appendBytes([]byte(c.Version), []byte(c.Issuer), []byte(c.TargetGS), []byte(c.TargetSatellite), c.Token[:], c.SID[:], c.C1, c.C2, int64Bytes(c.NotBefore), int64Bytes(c.ExpiresAt), int64Bytes(c.SessionDeadline)), nil
}

func decodeSPEARCookie(data []byte) (spearCookieClaims, error) {
	var c spearCookieClaims
	if f, e := splitLengthPrefixed(data, 11); e == nil && string(f[0]) == "SPEAR-A-COOKIE-2" {
		if len(f[1]) > 128 || len(f[2]) > 128 || len(f[3]) > 128 || len(f[4]) != 32 || len(f[5]) != 32 || len(f[8]) != 8 || len(f[9]) != 8 || len(f[10]) != 8 {
			return c, ErrInvalidRequest
		}
		c.Version = string(f[0])
		c.Issuer = string(f[1])
		c.TargetGS = string(f[2])
		c.TargetSatellite = string(f[3])
		copy(c.Token[:], f[4])
		copy(c.SID[:], f[5])
		c.C1 = f[6]
		c.C2 = f[7]
		c.NotBefore = int64(binary.BigEndian.Uint64(f[8]))
		c.ExpiresAt = int64(binary.BigEndian.Uint64(f[9]))
		c.SessionDeadline = int64(binary.BigEndian.Uint64(f[10]))
		return c, nil
	}
	return c, ErrInvalidRequest
}

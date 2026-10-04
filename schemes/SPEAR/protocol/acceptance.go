package spear

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"github.com/accumulators-agg/bp/bpacc"
	mcl "github.com/alinush/go-mcl"
	"sync"
	"time"
)

// Serialized through RevocationPayload, never by dumping the setup object.
type SPEARRevocationState struct {
	Context             [32]byte
	IssuedAt, ExpiresAt int64
	Digest              mcl.G1
	Signature           []byte
}

func RevocationPayload(s SPEARRevocationState) []byte {
	return appendBytes([]byte("SPEAR-A-REVOCATION-1"), s.Context[:], int64Bytes(s.IssuedAt), int64Bytes(s.ExpiresAt), s.Digest.Serialize())
}

// NCC authenticates the digest. Honest publication of the corresponding R is
// required; the UE checks its computed digest against this signed digest.
func SignSPEARRevocation(key ed25519.PrivateKey, d mcl.G1, issued, expires int64, context [32]byte) (SPEARRevocationState, error) {
	s := SPEARRevocationState{Context: context, IssuedAt: issued, ExpiresAt: expires, Digest: d}
	if expires <= issued || !d.IsValid() || !d.IsValidOrder() {
		return s, ErrInvalidRequest
	}
	var err error
	s.Signature, err = Sign(key, RevocationPayload(s))
	return s, err
}

type SPEARCredentialPolicy struct {
	M1, M2              mcl.Fr
	NotBefore, NotAfter int64
}

type spearPending struct {
	Binding   [32]byte
	StateTime int64
	Deadline  int64
}

type SPEARAccepted struct {
	SID      [32]byte
	C1, C2   mcl.G1
	Deadline int64
}

// Reference state machine. One instance is the atomic acceptance authority.
// Store must not be copied. Distributed replicas need equivalent transactions.
type SPEARAcceptor struct {
	mu             sync.Mutex
	params         Params
	vk             VerificationKey
	audit          AuditPublicKey
	acc            bpacc.BpAcc
	revKey         ed25519.PublicKey
	policies       []SPEARCredentialPolicy
	verifierCache  *spearVerifierCache
	policyBases    []mcl.G2
	state          SPEARRevocationState
	pending        map[[32]byte]spearPending
	now            func() time.Time
	maxSession     int64
	clockHighWater int64
}

// Called with mu held. A clock rollback fails closed until time catches up.
// Persist this watermark together with the other protocol state in deployment.
func (a *SPEARAcceptor) clockNow() int64 {
	n := a.now().Unix()
	if n < a.clockHighWater {
		return -1
	}
	a.clockHighWater = n
	return n
}

// SPEARVerifierOptions selects a time/memory tradeoff, not weaker checks.
type SPEARVerifierOptions struct{ DisablePairingCache bool }

func NewSPEARAcceptor(params *Params, vk *VerificationKey, audit *AuditPublicKey, acc *bpacc.BpAcc,
	revKey ed25519.PublicKey, policies []SPEARCredentialPolicy, maxSession time.Duration) (*SPEARAcceptor, error) {
	return NewSPEARAcceptorWithOptions(params, vk, audit, acc, revKey, policies, maxSession, SPEARVerifierOptions{})
}

func NewSPEARAcceptorWithOptions(params *Params, vk *VerificationKey, audit *AuditPublicKey, acc *bpacc.BpAcc,
	revKey ed25519.PublicKey, policies []SPEARCredentialPolicy, maxSession time.Duration, options SPEARVerifierOptions) (*SPEARAcceptor, error) {
	if params == nil || vk == nil || audit == nil || !spearAccReady(acc) || len(vk.Beta) != 3 || len(revKey) != ed25519.PublicKeySize || len(policies) == 0 || maxSession < time.Second || !params.G2.IsEqual(&vk.G2) {
		return nil, ErrInvalidRequest
	}
	for _, g := range []mcl.G1{params.G1, audit.Gamma, audit.IdentityBase, acc.G, acc.A[0]} {
		if g.IsZero() || !g.IsValid() || !g.IsValidOrder() {
			return nil, ErrInvalidRequest
		}
	}
	for _, g := range []mcl.G2{params.G2, acc.H, acc.VK[1], acc.B[0], acc.PedVK[0]} {
		if g.IsZero() || !g.IsValid() || !g.IsValidOrder() {
			return nil, ErrInvalidRequest
		}
	}
	for _, g := range append([]mcl.G2{vk.Alpha, acc.VK[1]}, vk.Beta...) {
		if !g.IsValid() || !g.IsValidOrder() {
			return nil, ErrInvalidRequest
		}
	}
	for _, p := range policies {
		if p.NotBefore >= p.NotAfter || !p.M1.IsValid() || !p.M2.IsValid() {
			return nil, ErrInvalidRequest
		}
	}
	a := &SPEARAcceptor{params: Params{G1: params.G1, G2: params.G2}, vk: VerificationKey{G2: vk.G2, Alpha: vk.Alpha, Beta: append([]mcl.G2(nil), vk.Beta...)},
		audit:  AuditPublicKey{Gamma: audit.Gamma, IdentityBase: audit.IdentityBase},
		acc:    bpacc.BpAcc{G: acc.G, H: acc.H, VK: append([]mcl.G2(nil), acc.VK[:2]...), A: append([]mcl.G1(nil), acc.A[:1]...), B: append([]mcl.G2(nil), acc.B[:1]...), PedVK: append([]mcl.G2(nil), acc.PedVK[:1]...)},
		revKey: append(ed25519.PublicKey(nil), revKey...), policies: append([]SPEARCredentialPolicy(nil), policies...), pending: make(map[[32]byte]spearPending), now: time.Now, maxSession: int64(maxSession / time.Second)}
	if !options.DisablePairingCache {
		a.verifierCache = newSPEARVerifierCache(&a.params)
	}
	for _, rule := range a.policies {
		var base mcl.G2
		mcl.G2MulVec(&base, []mcl.G2{a.vk.Beta[1], a.vk.Beta[2]}, []mcl.Fr{rule.M1, rule.M2})
		mcl.G2Add(&base, &base, &a.vk.Alpha)
		a.policyBases = append(a.policyBases, base)
	}
	return a, nil
}

func (a *SPEARAcceptor) InstallState(s SPEARRevocationState) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clockNow()
	if now < 0 || s.Context != HashBytes(spearAccContext(&a.acc)) || s.ExpiresAt <= s.IssuedAt || s.ExpiresAt-s.IssuedAt > 300 || s.IssuedAt > now || now >= s.ExpiresAt || s.IssuedAt <= a.state.IssuedAt || !s.Digest.IsValid() || !s.Digest.IsValidOrder() || Verify(a.revKey, RevocationPayload(s), s.Signature) != nil {
		return ErrInvalidRequest
	}
	s.Signature = append([]byte(nil), s.Signature...)
	a.state = s
	a.pending = make(map[[32]byte]spearPending)
	return nil
}

func (a *SPEARAcceptor) Challenge(binding [32]byte, ttl time.Duration) ([]byte, mcl.G1, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clockNow()
	if now < 0 || binding == [32]byte{} || ttl < time.Second || ttl > 5*time.Minute || now >= a.state.ExpiresAt {
		return nil, mcl.G1{}, ErrInvalidRequest
	}
	for n, p := range a.pending {
		if now >= p.Deadline {
			delete(a.pending, n)
		}
	}
	if len(a.pending) >= 4096 {
		return nil, mcl.G1{}, ErrInvalidRequest
	}
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, mcl.G1{}, err
	}
	if _, exists := a.pending[n]; exists {
		return nil, mcl.G1{}, ErrInvalidRequest
	}
	deadline := now + int64(ttl/time.Second)
	if deadline > a.state.ExpiresAt {
		deadline = a.state.ExpiresAt
	}
	a.pending[n] = spearPending{Binding: binding, StateTime: a.state.IssuedAt, Deadline: deadline}
	return append([]byte(nil), n[:]...), a.state.Digest, nil
}

func (a *SPEARAcceptor) Accept(binding [32]byte, wire []byte) (*SPEARAccepted, error) {
	// Decode to owned immutable values; do not accept mutable caller-owned proofs.
	msg, err := UnmarshalSPEAR(wire)
	if err != nil {
		return nil, err
	}
	var n [32]byte
	copy(n[:], msg.RSat)
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clockNow()
	p, ok := a.pending[n]
	if now < 0 || !ok || p.Binding != binding || now >= p.Deadline || now >= a.state.ExpiresAt || p.StateTime != a.state.IssuedAt {
		return nil, ErrInvalidRequest
	}
	// Reserve/consume before expensive work; even failed attempts need a fresh nonce.
	delete(a.pending, n)
	deadline := int64(0)
	var policy *mcl.G2
	for i, rule := range a.policies {
		if msg.M1.IsEqual(&rule.M1) && msg.M2.IsEqual(&rule.M2) && now >= rule.NotBefore && now < rule.NotAfter {
			deadline = rule.NotAfter
			policy = &a.policyBases[i]
			break
		}
	}
	if deadline == 0 || !a.verifyOwned(msg, policy) {
		return nil, ErrInvalidRequest
	}
	// State lock covers verification; check wall time again at the linearization point.
	now = a.clockNow()
	if now < 0 || now >= p.Deadline || now >= a.state.ExpiresAt || now >= deadline {
		return nil, ErrInvalidRequest
	}
	if cap := now + a.maxSession; deadline > cap {
		deadline = cap
	}
	var sid [32]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	return &SPEARAccepted{SID: sid, C1: msg.C1, C2: msg.C2, Deadline: deadline}, nil
}

// Commit the accepted audit record at the GS before granting service or issuing
// cookies. The fingerprint ties an authorized opening to these exact ciphertexts.
func SPEARAuditFingerprint(r SPEARAccepted) [32]byte {
	return sha256.Sum256(appendBytes([]byte("SPEAR-A-AUDIT-1"), r.SID[:], r.C1.Serialize(), r.C2.Serialize(), int64Bytes(r.Deadline)))
}

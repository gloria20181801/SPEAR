# SPEAR API and execution

Start with `schemes/SPEAR/cmd/demo/main.go`. The protocol package is deliberately
separate from the demonstration and experiment harnesses.

1. Initialize MCL with BLS12-381 once per process. `Setup(3)`, `Keygen` and
   `SignCred` provide the three-attribute credential. The library's attribute
   order is **[hidden identity m3, public m1, public m2]**; the corresponding
   `VerificationKey.Beta` entries use that order.
2. `SetupSPEARPublicAccumulator` generates public accumulator parameters.
   It returns no setup trapdoor. `GenerateAuditKeys` demonstrates two-share
   audit setup; only `AuditPublicKey` is passed to the prover and verifier.
   The two returned shares belong with separate auditors. The demo generates
   both in one process for reproducibility, not as a distributed key ceremony.
3. `SingleNonMemPrecompute` prepares a reusable witness for a non-revoked
   identity. The caller must authenticate the revocation publication and
   check that its list matches the accepted digest.
4. `NewSPEARProverCache` stores immutable credential-bound work. For each
   authentication, call `PrecomputeSPEARToken`, then `cache.Precompute`.
   These fresh one-time objects are private and must never be serialized.
5. Install a signed revocation digest with `SPEARAcceptor.InstallState`,
   obtain a challenge with `Challenge`, and complete the proof with
   `SPEARFullToken.Finish`. The result is the final compact message.
6. `SPEARAcceptor.Accept` validates the message and consumes the challenge.
   Bindings must come from an authenticated session context. The in-process
   demo supplies a random binding to demonstrate the API; it does not
   authenticate a network peer. Transport adapters are application concerns
   and their handshakes are not part of the CPU benchmark.
7. Register the accepted record with `SPEARHandoverAuthority.Register` before
   service release. `Issue` creates an encrypted same-GS or signed cross-GS
   cookie. The **target GS** calls `Consume` for its authenticated satellite.
8. For authorized opening, `SPEARAuditPartial` computes each auditor's
   contribution and `SPEARCombineOpening` returns the identity group element.
   Match that element against the enrollment mapping; do not solve a discrete
   logarithm to recover an identifier.

## Caches and representation

Credential-bound caches must be rebuilt when credential, attributes, issuer,
audit key or accumulator parameters change. Digest-bound tokens must match
the current state. A copied token handle shares the same consumption state;
success and failure both consume it. Go does not guarantee secret erasure.

The receiver's public pairing cache is enabled by default. Disabling it through
`SPEARVerifierOptions` changes a time/memory tradeoff, not the checked relations.
The final compact decoder reconstructs the omitted proof commitments and
checks the complete Fiat–Shamir challenge. No older external access encoding
or JSON cookie format is accepted. Expanded values used internally to compute
the transcript are not alternative public protocol versions.

Some domain-separation byte strings retain their frozen identifiers to preserve
the transcript definition. They are constants, not switches enabling earlier
protocol variants. The public Go API uses SPEAR names.

## Scope

Session, revocation and replay stores are in-memory reference implementations.
Deployment requires atomic durable state, authenticated publishers/channels,
trusted setup and the paper's auditor-exposure assumptions. In particular,
pooling both audit shares permits opening. The implementation does not prove
organizational separation or retroactive revocation of already admitted
handover sessions. Handover remains bounded by its original session expiry.

Tests check correctness, malformed or modified presentations, nonce/cookie
replay, stale state, deadlines, one-time-token ownership, pairing-cache
agreement and two-share opening. Passing tests does not constitute a new
formal security proof. The accompanying final protocol and restricted model
remain the basis of the paper's claims.

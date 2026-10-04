# Measurement boundaries

## How to run and interpret results

`scripts/benchmark.sh` starts three independent processes per scheme. Each
stage has five warm-ups and 300 individual timing samples per process.
`scripts/analyze.py` saves individual nanosecond samples, mean milliseconds,
sample variance in ms², and a 95% Student-t confidence interval across the
three process means (df=2). No outlier is discarded. `RUNS=1` is a smoke run
and deliberately leaves CI columns empty. Confidence intervals describe the
process-mean estimate, not individual-request percentiles.

Use the same native MCL build, host and CPU policy for all schemes.
`GOMAXPROCS=1` is the default. `CPU_INDEX` optionally pins the process to an
available logical CPU; it does not set CPU frequency. Network propagation,
queueing, TLS handshakes and persistent storage are excluded. Scheme-specific
key agreement, signatures and encryption are included when the measured flow
requires them. Some comparison flows operate on in-memory objects rather than
serialized packets; see COMPARISON_PROFILES.md.

Role timing partitions one local execution into role segments. A sum of role
means is not a measured network round trip, and separate confidence intervals
must not be added to form an interval for a total. The direct whole-flow stages
are available for total CPU timings.

## SPEAR

- `access_UE_precompute`: fresh one-time preparation with a reusable witness
  and credential-bound cache.
- `access_UE_online_finish`: finish after the satellite challenge, with the
  fresh one-time token already prepared.
- `access_UE_total_cached_witness`: preparation plus completion; excludes
  rebuilding a still-valid witness.
- `access_LEO_accept`: canonical compact decoding, policy checks, complete
  joint verification and nonce consumption.
- `access_GS_register`: registration of an already accepted audit record.
- `access_all_roles_cached_witness`: challenge, UE, satellite acceptance and
  GS registration in one measured local execution.
- `handover_*_source_issue`: source-GS cookie preparation.
- `handover_same_GS_target_consume`: authenticated same-GS cookie consumption.
- `handover_cross_GS_target_consume`: first import at a fresh target-GS
  authority. The authority constructor is outside the timer; point parsing,
  signature verification, import and replay checks are inside.

The GS verifies the handover cookie. UE/LEO forwarding must not be presented
as local LEO decryption or verification. Cookie issuance is not free merely
because it happens ahead of a subsequent handover. Session deadlines cannot
be extended by issuing another cookie.

## Scalability

`scripts/scalability.sh` evaluates list sizes 1, 4, 16, 64, 256, 1024, 4096,
16384. `IDRL_SIZES=1,64` requests a smaller explicit subset. Each process uses
a fixed public-parameter capacity of 32768. Setup is outside the timers.

The access experiment separates digest creation, witness rebuilding, one-time
preparation, online finishing, full proving, satellite acceptance and the
first path after a list update. Fast stages use 100 samples plus five warm-ups;
expensive stages use 100/30/12 samples for small/medium/large lists, with 5/3/3
warm-ups. Exact counts are in raw output.

The underlying witness experiment measures public `(A,B)` in G2×G1:

- Prover: rebuild the list polynomial, compute the non-membership witness and
  convert the scalar coefficient to the G2 element A.
- Verifier: call the accumulator's direct verification relation using the
  identity, digest and witness. Public `e(G,H)` is precomputed once; there is
  no identity-dependent verification cache.
- Size: compressed A (96 B) plus B (48 B), always 144 B. Identity, digest,
  public parameters and framing are excluded.

Witness prover sample counts match the slow-stage schedule above. Verification
uses 300 samples plus 20 warm-ups. Every generated witness is verified outside
its generation timer. Negative and serialization checks run before timings.
This direct primitive reveals its queried identity to the verifier; anonymity
in SPEAR is supplied by the joint zero-knowledge proof, whose time and message
size are different. A witness may be reused while the revocation state remains
unchanged; fresh proof randomness is still required for each authentication.

The shipped reference witness CSVs are measurements from the original server
(Xeon Gold 6240R, Go 1.24.7, BLS12-381/MCL, three processes). They are examples,
not results from the reader's machine. Regenerate statistics from new logs
before writing new performance claims.

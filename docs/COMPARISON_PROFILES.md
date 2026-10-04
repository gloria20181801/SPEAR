# Comparison profiles

These implementations reproduce the selected published algorithms for local CPU
comparison. They are not original-author releases. This artifact uses BLS12-381
as the common **main authentication group**, with the auxiliary suites below.

| Scheme | Included flow | Main group | Auxiliary algorithms |
|---|---|---|---|
| SPEAR | Three-attribute compact access; same-/cross-GS cookies | BLS12-381 | Ed25519, AES-256-GCM |
| AAKA | Four-attribute issuance and complete SN authentication | BLS12-381 | X25519, Ed25519, AES-128-CTR, HMAC-SHA256 |
| PkT-SIN | Three attributes, two disclosed; access and S1/S2/S3 | BLS12-381 G1, no pairing | Ed25519, AES-128-GCM |
| AnFRA | Anonymous roaming, preparation and opening | BLS12-381 Type-3 port | P-256 ECDSA |
| MEC-STIN | Access, pre-handover and online handover | BLS12-381 G1 | AES-128-GCM, SHA-256 |

## AAKA

*AAKA: An Anti-Tracking Cellular Authentication Scheme Leveraging Anonymous
Credentials*, NDSS 2024. `paper_reference.go` contains the selected Appendix-D/F
interpretation and packet cryptography. `paper_reference_test.go` exercises it.

The published mixed scalar/group expressions are implemented with identity
`m4` encoded as `[m4]G1`, scalar `B=-m4`, and the Appendix-D/F transmitted
`y2/y3` values. The request suite uses X25519, X9.63/SHA-256, AES-128-CTR and
an 8-byte HMAC; the presentation channel uses separate encryption/MAC keys
and full HMAC. These are explicit executable choices. We measure AAKA as a
published-algorithm performance reproduction, without redesigning its security
mechanism. No dedicated satellite handover algorithm is supplied; report N/A,
not zero latency. SIM/USIM and a mobile-core deployment are outside scope.

## PkT-SIN

*PkT-SIN: A Secure Communication Protocol for Space Information Networks*,
IEEE TIFS, 2024. `reference_issue.go`, `reference_show.go` and
`reference_signature.go` implement the Appendix-B credential relations.
`reference_process_test.go` and `roles_test.go` implement access and handover.

The issuer relation includes index 0 consistently with the credential equation,
and the challenge binds the message M. Token serialization includes its proof
challenge C. The profile uses three attributes with two disclosed. S1 changes
LEO while retaining the GS session; S2 changes GS; S3 repeats full access with
new infrastructure. Required encryption/signature work is executed. Durable
NCC token reporting and an independent interoperable packet decoder are not
implemented. Message-object computations must not be described as a complete
deployed network stack.

## AnFRA

*AnFRA: Anonymous and Fast Roaming Authentication for Space Information
Network*. `reference_type3.go` maps the published symmetric-pairing relations
to paired source-group generators with common exponents in Type-3 groups.
This is explicitly a port, not a claim that the original paper used BLS12-381.

The reproduction covers P-256 ECDSA pre-negotiation/response, randomized
temporary identities, user proof, satellite/GS/user checks, key agreement and
opening. `reference_cached.go` implements the fixed-pairing cache. Cached and
uncached timings are identified in the output. Anonymous roaming is not
relabeled as a lightweight cookie handover. No distributed revocation service
or network propagation is simulated.

## MEC-STIN

Kwon et al., *An Efficient Handover Authentication Scheme for 6G-Enabled
Space-Terrestrial Integrated Networks With Mobile Edge Computing*, IEEE TIFS,
2025, reference [28] in the SPEAR manuscript.

`protocol.go` reproduces registration, access, pre-handover, online handover and
local revocation lookup. The common-group profile uses BLS12-381 G1; it does
not claim to reproduce a paper-specific P-256 timing. The fuzzy-verifier
modulus is 16. The published PHP1/PHP2 expressions for Vs1 differ; this
implementation uses PHP2's full expression at both ends. This is a disclosed
interpretation, not an author-confirmed erratum. Adjacent satellites receive
the shared SSK needed for decryption. AES-128-GCM and byte encodings are suite
choices where the paper does not completely specify them.

Online handover retains the LEO challenge followed by the UE response.
Pre-handover preparation is reported separately. Revocation measurement is
local lookup/unmasking, excluding global list distribution.

## SPEAR

The final profile has a 1,234-byte compact access message, fixed credential
and public pairing caches, one-use preprocessing, and GS cookie verification.
The additional fixed-base-table experiments and earlier UE–LEO request-response
variant are not part of this repository. Full authentication and online-only
completion are separate measurements. All schemes retain their own functional
and trust assumptions; timing alone is not a feature-equivalent ranking.

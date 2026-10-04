# AAKA reproduction

Use `source ../../scripts/env.sh` and `go test ./...` after native setup.
`paper_reference.go` contains the published-algorithm presentation and packet
reconstruction; `setup.go`, `issue.go` and related helpers provide its credential
operations. Correctness tests cover issuance, presentation, opening and packet
round trips. `roles_test.go` measures UE/SN work.

The profile uses BLS12-381 plus auxiliary X25519/Ed25519. No dedicated satellite
handover is implemented. See [profile choices](../../docs/COMPARISON_PROFILES.md).
Use `scripts/benchmark.sh` from the repository root for performance results.

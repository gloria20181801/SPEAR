# AnFRA reproduction

Use `source ../../scripts/env.sh` and `go test ./...` after native setup.
`reference_type3.go` contains the explicit Type-3 port;
`reference_cached.go` provides fixed-pairing caching. The process and role
tests cover roaming authentication, preparation, responses and opening.

The main group is BLS12-381; P-256 ECDSA remains an auxiliary algorithm.
The port is not presented as the paper's original symmetric-pairing backend.
See [profile choices](../../docs/COMPARISON_PROFILES.md).

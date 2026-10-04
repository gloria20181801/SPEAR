# PkT-SIN reproduction

Use `source ../../scripts/env.sh` and `go test ./...` after native setup.
`reference_issue.go`, `reference_show.go` and `reference_signature.go` implement
the selected Appendix-B credential/proof relations. The process tests and
`roles_test.go` cover access and all three handover cases.

The profile uses three attributes, two disclosed, BLS12-381 G1 and Ed25519.
Network transport and durable NCC token reporting are outside this reference.
See [profile choices](../../docs/COMPARISON_PROFILES.md).

# MEC-STIN reproduction

Use `source ../../scripts/env.sh` and `go test ./...` after native setup.
`protocol.go` contains registration, access, pre-handover, online handover
and local revocation functions. `roles_test.go` partitions authentication work
by UE/HAP/LEO role. Preparation and online handover are separate measurements.

This repository uses the common-group BLS12-381 G1 profile and AES-128-GCM.
The interpretation of the paper's differing PHP1/PHP2 expressions is recorded
in [profile choices](../../docs/COMPARISON_PROFILES.md).

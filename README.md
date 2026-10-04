# SPEAR: implementation and comparison artifact

The compact SPEAR implementation and reproductions of
AAKA, PkT-SIN, AnFRA, and MEC-STIN. The four comparison implementations are
reconstructions of published algorithms, not the original authors' software.

SPEAR uses BLS12-381, a three-attribute credential, a fused joint proof, reusable
non-membership witnesses, one-use prover preprocessing, and cached satellite
verification. 

## Quick start (Linux)

Requirements: Go **1.24.7 or newer**, Python **3.8+**, Git, CMake, a C/C++ compiler,
and CGO. On Debian/Ubuntu, native build prerequisites include `build-essential`,
`cmake`, `git`, `libgmp-dev`, and `libssl-dev`. Install Go separately if your
distribution package is older than the required version.

```bash
bash scripts/build-native.sh
source scripts/env.sh
bash scripts/test.sh
```

Native MCL is pinned and installed under `.deps/`; no system-wide library
installation is needed. Go module versions are locked in each scheme's
`go.mod`/`go.sum`. To use an existing compatible installation, set
`SPEAR_NATIVE_PREFIX=/path/to/native` before sourcing `scripts/env.sh`.

`test.sh` runs all five correctness suites and the SPEAR demonstration:

```bash
cd schemes/SPEAR
go run ./cmd/demo
```

The demo covers issuance, witness generation, compact access, two-share
identity opening, same-GS handover, cross-GS handover, and replay rejection.
It generates temporary keys in memory and does not require a server or VPN.

## Performance experiments

```bash
# Three independent process runs, raw samples, variance and 95% CI:
bash scripts/benchmark.sh

# Optional CPU pinning; choose a CPU available on your machine:
CPU_INDEX=2 bash scripts/benchmark.sh

# SPEAR access and underlying accumulator scalability, 1 to 16,384 entries:
bash scripts/scalability.sh

# Short execution check; one run does not produce confidence intervals:
RUNS=1 IDRL_SIZES=1,64 bash scripts/scalability.sh
```

Results are written to timestamped directories in `results/`. Correctness tests
skip performance experiments unless the scripts explicitly enable them. The
full scalability experiment may take several minutes. Measurements include
only the documented local protocol work, excluding TLS, network delay, and
persistent database transactions. Required protocol encryption, signatures,
and key agreement remain included. Read [measurement scope](docs/MEASUREMENTS.md)
before interpreting or comparing numbers.

## Editable figure

Install `matplotlib`, then:

```bash
python3 plots/witness.py
# For a new three-run scalability result:
python3 plots/witness.py --data results/scalability-TIMESTAMP/witness
# If Times New Roman is unavailable:
python3 plots/witness.py --font "DejaVu Serif"
```


## Layout

| Path | Contents |
|---|---|
| `schemes/SPEAR/protocol` | Final credential, accumulator, joint proof, receiver and handover code |
| `schemes/SPEAR/cmd/demo` | Executable complete SPEAR example |
| `schemes/AAKA` | Four-attribute AAKA reference and packet computations |
| `schemes/PKTSIN` | PkT-SIN Appendix-B proof, access and three handover cases |
| `schemes/AnFRA` | Explicit Type-3 pairing reproduction and roaming |
| `schemes/MECSTIN` | MEC-STIN access, handover preparation and online handover |
| `scripts` | Build, test, timing and statistical analysis |
| `plots` | Editable plotting source |
| `docs` | API guide, reproduction choices and measurement boundaries |

The main authentication groups are BLS12-381. Auxiliary X25519, Ed25519 and
P-256 operations used by particular schemes are listed in
[comparison profiles](docs/COMPARISON_PROFILES.md). There is no claim that every
operation across all five schemes uses the same curve or provides identical
functionality. AAKA has no separately implemented satellite handover algorithm.

## Use and attribution

See the [release validation record](docs/VALIDATION.md) for completed checks
and their scope. The release identifier is in `VERSION`.

This is a research artifact, with in-memory session and revocation state.
Transport authentication, durable replay protection and deployment key
management must be provided by an integrating system. See
[SPEAR API and scope](docs/SPEAR.md). Historical variants, private experiment
directories, paper PDFs, reviewer correspondence and deployment credentials
are not included.

Original contributions use [MIT](LICENSE). Adapted Coconut material and
dependencies retain their upstream terms: see [NOTICE](NOTICE) and
[third-party provenance](THIRD_PARTY.md). Two externally fetched dependencies
have no license file in the pinned module snapshots; this repository does not
vendor them or claim they are MIT-licensed.

[中文使用说明](README_zh.md)

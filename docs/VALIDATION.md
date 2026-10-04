# Release validation

Release: `2026-10-04-compact-gs`.

The cleaned artifact was validated on Linux, an Intel Xeon Gold 6240R host,
Go 1.24.7, Python 3.8, and the pinned BLS12-381 MCL build.

| Check | Result |
|---|---|
| Five scheme correctness suites | Passed |
| SPEAR complete demonstration | Passed |
| Compact message and underlying witness size | 1234 B and 144 B |
| Two-share identity opening | Matched the enrolled identity |
| Same-GS and cross-GS handover | Accepted; repeated cookies rejected |
| Five-scheme performance script | Three processes per scheme; 64 groups, 57,600 samples |
| Scalability script execution check | Three processes at IDRL sizes 1, 64, 1024; 33 groups, 10,860 samples |
| Statistical analysis | Sample variance and 95% CI generated; Python 3.8 compatibility verified |
| Private native MCL build and subsequent five-scheme tests | Passed using the public build and environment scripts |
| Witness plotting script | PNG/PDF/SVG generated; combined figure visually checked |

The native build started from a local Git clone of the pinned upstream MCL
revision and installed into the artifact's own `.deps` directory. A fresh
external network download and empty Go module cache were not tested.

The default scalability script supports all eight sizes up to 16384. The
three-size release check above must not be represented as a new full
eight-size experiment. The bundled reference witness CSVs come from the
earlier full eight-size, three-process measurement on the same server.

Correctness and benchmark checks support reproducibility; they are not an
independent cryptographic security audit. Timing values depend on the host.
The root `MANIFEST.sha256` identifies the files in this source distribution.

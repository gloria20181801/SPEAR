# Third-party notices and provenance

The root MIT license applies to original contributions for which the SPEAR contributors hold rights. It does not replace upstream terms. No external dependency source is vendored.

|Dependency / origin|Pinned version / source|Observed license|
|---|---|---|
|Native MCL, Mitsunari Shigeo|`e4c8bbe4af0013e00244c661836f3a3676f21024`|BSD-3-Clause; native COPYRIGHT retained in third_party|
|accumulators-agg/bp|`b4c52aff33ef` via go.mod|Apache-2.0; LICENSE retained|
|accumulators-agg/go-poly|`342b847a2704` via go.mod|No license file found in pinned module snapshot; external dependency only|
|alinush/go-mcl|`eb6000c9b115` via go.mod|No license file found in pinned module snapshot; external dependency only|
|magefile/mage|`v1.10.0`|Apache-2.0; LICENSE retained|
|sirupsen/logrus|`v1.7.1`|MIT; LICENSE retained|
|golang.org/x/crypto and x/sys|Exact module revisions in each go.mod/go.sum|BSD-3-Clause; LICENSE retained|
|Coconut Python implementation|[asonnino/coconut](https://github.com/asonnino/coconut)|Apache-2.0 upstream; historical local Go-port documentation attributes its origin here|

SPEAR credential helpers (`scheme.go`, `types.go`, `utils.go`) evolved from the local Coconut Go port. The exact original Python revision was not recorded in the supplied project. We retain the upstream attribution and Apache license for any adapted upstream material; the presence of a root MIT file must not be read as an exclusive relicense of that material. The SPEAR receiver and artifact tooling include original contributions.

The bilinear accumulator and non-membership construction builds on accumulators-agg/bp; its upstream license is included and its formula/source provenance is acknowledged. Comparison-paper algorithms are reimplementations from publications with choices described in docs/COMPARISON_PROFILES.md, not redistributed original-author software.

The two missing-license observations above do not constitute permission to relicense, vendor or commercially redistribute those dependency implementations. Clarify upstream permissions or select a reviewed licensed replacement if that is required for downstream redistribution. The package does not falsely label the complete dependency graph as MIT-only.

License texts are in `third_party/`; the exact module license inventory is preserved there. Build artifacts under `.deps/` are excluded from this source distribution. Upstream sources: https://github.com/herumi/mcl, https://github.com/accumulators-agg/bp, https://github.com/accumulators-agg/go-poly, https://github.com/alinush/go-mcl.

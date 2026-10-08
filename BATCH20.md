# v0.6: 20-input batch conversion and failure-driven fixes

## Batch results

The public trial now requires exactly 20 generated upstream configurations and attempts ordinary and bounded compilation independently for each input.

| Measurement | Result |
|---|---:|
| Public input configurations | 20 |
| Ordinary-mode converted inputs | 3 |
| Bounded-mode converted inputs | 8 |
| Sampled connection comparisons across both modes | 13,820 |
| Connection differences | 0 |
| Verification errors | 0 |
| Seeded synthetic configurations | 1,000 |
| Synthetic batches, 20 configurations each | 50 |
| Synthetic IPv4 / IPv6 configurations | 500 / 500 |
| Synthetic sampled connection comparisons | 760,000 |
| Synthetic connection differences | 0 |
| Automated tests | 78 passed |

The three ordinary-mode inputs are also among the eight bounded-mode inputs; these are not eleven distinct successfully converted inputs. Blocked inputs are never counted as successful conversion. Public inputs are generated fixtures, not verified production exports. Synthetic trials use explicit default-deny assumptions and single-IP mapped assets; their cases are not live packet probes or a universal equivalence proof.

## Problems found and fixed

1. **One mode's input failure prevented the other mode from running.** The batch runner now invokes and records each compiler independently. A regression case uses a group IP range that ordinary mode rejects but bounded mode can evaluate.
2. **Verification failures were mislabeled as adaptation failures.** Adaptation, compilation and comparison now have separate status/error fields. Verification errors cause a nonzero batch exit. A deliberately corrupted target rule is detected in regression tests.
3. **The independent comparison evaluator did not handle nested services, IPv6, family filters or address ranges.** Added its own service traversal and family-aware matching, with regression cases based on the authored IPv6 nested-service fixture. It does not use the compiler's resolver to obtain expected decisions.
4. **Adjacent allowed port partitions were split solely because source rule traces differed.** Bounded compilation now merges adjacent allowed ranges without merging gaps. Per-partition trace evidence remains in `source_rule_segments`; `source_rule_trace` is null when a merged rule has multiple trace segments. This can avoid unnecessary quota failures. A regression case converts ports 80 and 81 under a two-rule target budget (one allow and one deny).
5. **Ordinary compilation emitted cross-family peer rules for single-family local assets.** Peer expansion is now filtered by the matched local IP family. Regression coverage checks that an IPv4-only enforcement unit receives no IPv6 peer rules.

## Reproduce

Run from the repository root:

```bash
python3 complex-samples/run.py
python3 stress_trial.py --seeds 1000 > complex-samples/stress-report.json
python3 -m unittest discover -s . -v
```

`complex-samples/report.json` records all twenty inputs, both modes and comparison outcomes. Converted and blocked plans are saved under `complex-samples/results/<fixture>/`. Blocked plans contain no Security Group requests; rerunning invalidates stale successful candidates. `complex-samples/stress-report.json` records every twenty-configuration synthetic batch and seed range.

## Still blocked by design

Some public inputs have missing VM/group membership, abstract groups without assets, single-asset external-only coverage, services outside the supported leaf subset, or strict CIDRs with host bits set. These need missing data or additional semantic support. The tool does not silently widen a CIDR, fabricate membership, or replace an unknown endpoint with ANY.

Bounded mode still intentionally denies traffic outside distinct mapped same-family single-IP pairs, TCP/UDP ports 1–65535 and new connections. Full DFW migration, external-peer equivalence, multi-IP assets, live cloud deployment and rollback remain out of scope.

# v0.3 code review and hardening

Scope: policy compiler, raw export adapters, CLI input/output, tests, and documentation. Reviewed using the code-review-expert workflow. Changes address concrete correctness failures; they do not establish production readiness.

## Fixed findings

| Priority | Finding | Fix and evidence |
|---|---|---|
| P1 | Truthy strings could skip enabled rules or attest incomplete groups/exports | Require actual JSON booleans; regression tests cover `disabled="false"`, membership, and manifest flags |
| P1 | Duplicate group/service paths silently replaced earlier objects | Reject duplicate identities before indexing |
| P1 | Target IP collisions and explicit/retained mappings could contradict asset mappings | Canonical IP checks, mapping agreement, retained-range overlap checks; IPv6 aliases tested |
| P1 | Mixed ANY or malformed reference types could broaden interpretation | Reject mixed ANY and non-array reference values |
| P1 | Explicit empty scope silently inherited parent scope | Reject empty scope during adaptation |
| P1 | Failed reruns left previous successful JSON artifacts available | Atomically replace output with a blocked marker; subprocess regression tests |
| P2 | Quota checks happened after allocating all candidates | Enforce per-direction budget during expansion using counters and a per-rule cap |
| P2 | Duplicate JSON keys, invalid ordering types, and non-finite JSON numbers were accepted | Strict JSON reader and structural validation; 64 MiB input limit |

## Architecture

Validation is shared in validation.py; atomic JSON output handling is shared in output_io.py. The compiler remains responsible for policy semantics; adapters remain responsible for input normalization. No deployment abstraction or networking dependencies were added.

## Remaining work before production use

- Complete schema coverage: unsupported extension fields may still encode semantics the compiler cannot preserve. An input subset and operator review are required.
- A separate NSX collector must prove pagination, policy order, exclusion lists, inherited fields, snapshot freshness, and membership completeness. Manifest confirmations are assertions, not evidence.
- Build a broader source-vs-target connection evaluator, including address-set boundaries, multi-NIC cases, default policies, disabled rules, and randomized fixtures. The current eight demo checks are deliberately narrow.
- Verify generated requests against Tencent Cloud in an isolated environment, including instance associations, other attached Security Groups, default behavior, NAT, and routing.
- Real template/Cloud Firewall API adapters, dynamic tag membership synchronization, deployment snapshots, and rollback remain unimplemented.
- JSON replacement is atomic per file, not a transaction across JSON and CSV. Consumers must check plan.json status and CLI exit code. Concurrent writers to the same output path are unsupported.
- The 64 MiB limit bounds individual files, not total input or CPU use. Large group/asset sets still require performance testing; pending rule expansion is bounded, but source collection can remain large.

## Validation

39 automated tests passed, including two CLI subprocess failure-recovery tests. The public analyzer sample still compiles, and all eight offline demo connection cases pass. No live NSX/Tencent Cloud calls were made.

## v0.4 update

A separate bounded compiler adds Environment jump control flow and negation evaluation within an explicitly limited endpoint domain. Ordinary compilation remains conservative. 52 tests pass; 11,104 finite-domain sampled connections agree with a separate first-match evaluator. Coverage and deliberate outside-domain denial are recorded in each bounded plan. This does not resolve full-schema, collector, live deployment or rollback requirements above.

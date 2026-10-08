# Complex public fixture trial / 复杂公开样例试跑

Run from repository root: `python3 complex-samples/run.py`.

Sources and pinned revision: [SOURCE.md](SOURCE.md). All eight inputs are public generated test configurations from np-guard/vmware-analyzer, not verified customer production exports. Original files are retained unmodified under their Apache-2.0 license.

| Fixture | VMs | Source rules | Result | Connection checks |
|---|---:|---:|---|---:|
| Example1aRedundantRuleInOut | 2 | 4 | Review required; 10 generated rules | 44; no differences |
| ExampleGroup4 | 5 | 2 | Review required; 14 generated rules | 440; no differences |
| Example2 | 11 | 16 | Blocked: JUMP_TO_APPLICATION | — |
| ExampleHogwarts | 11 | 9 | Blocked: JUMP_TO_APPLICATION | — |
| ExampleAppWithGroups | 5 | 8 | Blocked: negation and unsupported services | — |
| ExampleExprAndCondsExclude | 9 | 5 | Blocked: negation | — |
| ExampleExprOrCondsExclude | 9 | 5 | Blocked: negation | — |
| ExampleExprSingleScope | 3 | 9 | Blocked: unresolved group membership | — |

Machine-readable diagnostics: [report.json](report.json).

## What was checked

For successfully compiled inputs, a separate first-match evaluator compares source NSX endpoint decisions with generated target ingress/egress decisions. It checks every ordered pair of distinct mapped VMs, TCP/UDP, selected ports, and port-range boundaries and adjacent values. Source and target both assume default denial when no rule matches.

Mapped IPs are synthetic documentation addresses; stateful, direction and IPv4 defaults are explicit trial assumptions. Resolved VM membership comes from the fixture and mapping. Tag and nested expressions are not executed. The cases cover new connections, not return traffic, real cloud binding, external endpoints, self-connections, multiple NICs, IPv6 or routing. Sampled agreement is not a complete equivalence proof.

Unsupported input must block the entire Security Group request list. Regression tests check that the known unsupported samples remain blocked; the runner asserts that no requests are returned for blocked plans.

## 中文结论

8 份复杂公开生成样例，55 台 VM（按样例分别计数）、58 条源规则。
2 份转换成功并完成 484 个离线新连接比较，没有发现差异；6 份因明确不支持的语义或缺少完整成员而阻断。

接下来应优先实现分类跳转的控制流分析、带有明确资产全集的排除集合计算，以及更完整的组成员采集。不能将 JUMP_TO_APPLICATION 直接当成 ALLOW，也不能用 ANY 替代未解析对象。

## v0.4 bounded-mode results

Ordinary mode retains its existing unsupported-rule blocks. In the explicitly selected bounded mode, Example2, ExampleHogwarts, both exclusion-expression examples, ExampleGroup4 and the redundant-rule example compile. ExampleAppWithGroups remains blocked by unsupported services; ExampleExprSingleScope remains blocked by incomplete membership.

11,104 sampled mapped-pair connection comparisons show no differences in the IPv4 TCP/UDP port 1–65535 domain. Status is bounded_review_required. The default deny deliberately restricts traffic outside that domain. This does not prove full NSX equivalence. Generated bounded plans are under results/<fixture>/bounded-plan.json.

Jump semantics reference: https://developer.broadcom.com/xapis/inventory/latest/data-structures/InlineNsxRule1/

## v0.5 expansion

Ten more unmodified public generated inputs cover segments, external ranges, multiple scopes and abstract groups. See SOURCE.md. Of 18 total inputs, ordinary compilation succeeds for 3 and bounded compilation for 8; others remain explicitly blocked. Public successful cases have 1,044 ordinary and 12,776 bounded sampled connection comparisons without differences.

Public input IPs are not used as real discovered asset IPs: the runner supplies synthetic documentation-address mappings. Segment topology is not implemented or inferred. External-only examples cannot establish pairwise equivalence; single-asset domains are blocked.

The separate stress_trial.py creates 40 deterministic configurations, half IPv6, with category jumps, negation, scopes, family filters and port boundaries. Its independent direct-membership evaluator compares 30,400 connections. See stress-report.json. These are authored fixtures, not additional public or production exports.

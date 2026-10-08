# NSX → Tencent Cloud Micro-segmentation Migration Tool v0.2

English | [简体中文](README.zh-CN.md)

An offline Python 3 tool using only the standard library. It generates Tencent Cloud Security Group rule candidates, parameter template candidates, and Cloud Firewall policy review data from NSX DFW configuration and asset mappings.

This is a migration planning prototype. It does not connect to NSX or Tencent Cloud, read credentials, create resources, deploy rules, or perform rollback. Production configurations have not been validated.

## Quick start

Run from the repository root:

```bash
python3 migrate.py --snapshot examples/snapshot.json --mapping examples/mapping.json --out result
python3 -m unittest discover -s . -v
```

Exit codes:

- `0`: A plan was generated for review. This does not establish policy equivalence or deployment readiness.
- `2`: Conversion is blocked. The entire Security Group request list is empty.
- `1`: Invalid input or an input/output error.

## Outputs

The tool writes `plan.json` and `issues.csv`.

| Field | Contents |
|---|---|
| `security_group_requests` | Candidates using Tencent Cloud's `SecurityGroupId` and `SecurityGroupPolicySet` structure. Generated only when no blocking errors exist; do not append directly to existing rules. |
| `cloud_firewall_review` | Intermediate connection policies retaining source scope, order, and logging intent. These are not Cloud Firewall API requests. DFW enforcement scope must be reconciled with firewall routing and inspection paths. |
| `parameter_template_candidates` | Deduplicated addresses and protocol/port values. These are not template creation requests; no template IDs or references are created. |
| `group_inventory` | Original group expressions retained for reviewing tag and membership mappings. |
| `provenance` | Collection metadata and explicit assumptions supplied by the adapter, when present. |

## Normalized input contract

The compiler accepts normalized NSX-T/4.x Policy JSON snapshots; see [examples/snapshot.json](examples/snapshot.json). It does not directly accept arbitrary raw API responses, console CSV files, or NSX-V XML. The adapter supports the specific formats described below.

Collectors or manual preparation must:

1. Collect all policies, rules, groups, and services, consuming every API page. Place rules in the `rules` array.
2. Assign a unique global `effective_order` based on the actual category, policy, and rule order. Sorting only by a rule's `sequence_number` is insufficient.
3. Resolve policy inheritance, including `scope` and `stateful`, for each rule. Supply explicit `direction` and `ip_protocol` values.
4. Populate group `members` with a complete resolved IP membership snapshot from `/members/ip-addresses`. Set `members_complete=true` only after checking completeness. Tag and nested expressions are retained but not evaluated.
5. Review the DFW exclusion list, default policies, Ethernet/L2 rules, NICs, and IP discovery completeness. Missing rules or assets cannot be detected from an incomplete snapshot.
6. Provide Policy `service_entries`. Only TCP/UDP destination-port services are supported; nested service references are unsupported.

Member addresses must be individual IPs or strict CIDRs, not IP range strings. Record the collection time and refresh group membership before cutover; the compiler does not validate snapshot freshness.

## Asset mapping and changed IP addresses

Each entry in `mapping.assets` represents one target enforcement unit. Use a stable VM or CMDB identifier for `id`. Pair `old_ips` and `new_ips` positionally, and supply the intended target `security_group_id`.

This version requires a dedicated Security Group for each enforcement unit, associated exclusively with that unit. Security Group IDs must be unique, and unmapped instances must not be added to those groups. The tool emits new IP `/32` or `/128` addresses rather than cloud Security Group references. Aggregating instances into role groups requires verifying that their complete effective policies are identical.

- `address_map`: Explicit additional old-address/CIDR to new-address/CIDR mappings. Address family and address-set size must remain the same; membership still requires review.
- `retain_addresses`: Explicit addresses or CIDRs for on-premises or third-party endpoints that remain unchanged.
- `ANY`: Preserved as IPv4/IPv6 all-address ranges, filtered by the rule's `ip_protocol`. Review these permissions as well.
- Duplicate old asset IPs are rejected. Overlapping address spaces and identity resolution across multiple VPCs are unsupported.
- NAT, mixed migration waves, replacement with managed services, and merging or splitting assets require explicit visible-address mappings and separate planning.

See [examples/mapping.json](examples/mapping.json).

## Conversion semantics and limits

The compiler uses scope and direction to generate ingress/egress rules for each mapped enforcement unit, only when its local addresses match the relevant endpoint. Partial NIC/address matches block conversion.

`ALLOW` becomes `ACCEPT`; `DROP` remains `DROP`. Relative order follows `effective_order`. No reverse business-access rules are added merely to permit return traffic.

Blocking conditions include incomplete groups, missing address mappings, negated groups, L7 profiles, non-stateful rules, `REJECT`, source-port restrictions, unknown services, no mapped enforcement endpoint, and exceeding the configured rule budget.

The default budget is 200 rules per Security Group per direction. **This is a tool budget, not a guarantee of account quotas.** Check the target region and account limits before deployment.

NSX per-rule logging produces a warning because it is not preserved in native Security Group candidates. Dynamic tag groups become membership snapshots; continuous synchronization is not implemented. Unknown extension fields do not receive comprehensive semantic validation. Inputs must stay within the supported subset.

## Recommended migration workflow

1. Collect a complete export and review the asset mapping. Start with one application whose dependencies are understood.
2. Create empty, dedicated Security Groups in an isolated target environment. Check default behavior, instance associations, and the combined effect of all other attached groups. The tool does not generate association operations.
3. Review the plan and confirm that implicit default denial matches the complete source policy. Represent source default-allow behavior explicitly in the snapshot.
4. Deploy reviewed rules through an SDK or IaC, preserving the complete rule list order. Deployment snapshots and rollback must be implemented separately.
5. Test allowed and denied connections using new sessions. Include DNS, authentication, monitoring, backup, and batch jobs.
6. Cut over in waves, refresh group membership, and remove temporary rules. Extend role-group aggregation, template creation, and Cloud Firewall API support after validating the PoC.

## Raw input adapters and demo

`adapt.py` supports the public `vmware-analyzer` resource JSON format and an AWS Labs NSX export directory. The compiler continues to consume normalized snapshots.

See [TRIAL.md](TRIAL.md) for the trial report in Chinese. The trial passed 17 tests and 8 offline connection checks. It used a generated public fixture and explicitly supplied demo IPs and missing fields; it was not a live NSX or Tencent Cloud test.

### Public sample

```bash
python3 adapt.py --format analyzer --input public-sample/Example1.json --mapping demo/mapping.json --manifest demo/manifest.json --out demo/normalized.json
python3 migrate.py --snapshot demo/normalized.json --mapping demo/mapping.json --out demo/result
python3 demo/verify.py
```

### AWS Labs export directory

The adapter follows the export file contract of [awslabs/import-export-for-nsx](https://github.com/awslabs/import-export-for-nsx): `dfw.json`, `dfw_details.json`, `cgw-groups.json`, and `services.json`, with optional `tags.json`. File names are configurable through the manifest. Extract the export archive before running:

```bash
python3 adapt.py --format aws-export --input /path/to/extracted-export --mapping /path/to/mapping.json --manifest /path/to/reviewed-manifest.json --out result/normalized.json
python3 migrate.py --snapshot result/normalized.json --mapping /path/to/mapping.json --out result/tencent-plan
```

Start with [examples/aws-manifest.json](examples/aws-manifest.json). Completeness confirmations default to `false`; fill them only after checking the export. Do not copy the demo assumptions into a production manifest.

- `policy_order` must list every policy exactly once in its effective NSX order, respecting category order.
- Rules with sequence numbers are sorted by those numbers. Missing sequence numbers require explicit confirmation that array order is effective order.
- `group_members` is keyed by group path, with resolved `ips` and a `complete` flag.
- Unconsumed API cursors block adaptation. A manifest assertion does not independently prove export completeness.

Membership snapshots may contain IPs of endpoints remaining on-premises. Explicitly retain those addresses or supply their actual peer-address mappings. Rules without a mapped Security Group enforcement endpoint block conversion and require wave-specific handling.

Original tag expressions and tag exports are retained for review. The adapter does not evaluate arbitrary tag expressions, assign cloud tags, or continuously synchronize group membership. AWS-format compatibility was tested using constructed fixtures, not an export collected from a live AWS/NSX environment.

## Official references

- [NSX Rule schema](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/schemas_Rule.html)
- [Exporting NSX groups, members, and services](https://knowledge.broadcom.com/external/article/429635/exporting-all-nsxt-security-groups-via-a.html)
- [Tencent Cloud Security Group data structures](https://cloud.tencent.cn/document/api/215/15824)
- [Creating Tencent Cloud Security Groups and rules](https://cloud.tencent.com/document/api/215/43279)

These references inform field design; they do not constitute vendor certification of this tool.

## License and attribution

Original tool code is licensed under [Apache-2.0](LICENSE). `public-sample/Example1.json` comes from `np-guard/vmware-analyzer`; its original Apache-2.0 license is retained. See [public-sample/SOURCE.md](public-sample/SOURCE.md) for the pinned revision and source.

The AWS Labs project was used only as a reference for the export file contract. Its source code was not copied.

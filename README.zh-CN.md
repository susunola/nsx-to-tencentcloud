# NSX → 腾讯云微隔离迁移工具 v0.2

[English](README.md) | 简体中文

Python 3 标准库离线工具。第一版以腾讯云为目标：输出安全组请求候选、参数模板候选和 Cloud Firewall 策略审阅数据。它是迁移规划编译器，不是生产一键迁移器。不会联网、创建资源、修改安全组或读取凭证。

## 快速运行

在本目录执行：

```bash
python3 migrate.py --snapshot examples/snapshot.json --mapping examples/mapping.json --out result
python3 -m unittest discover -s . -v
```

退出码：0 = 生成待审阅方案；2 = 存在阻断项，安全组请求整体为空；1 = 输入错误。0 不代表已验证等价或可上线。

输出 `plan.json` 和 `issues.csv`：

- `security_group_requests`：腾讯云 SecurityGroupId + SecurityGroupPolicySet 结构的候选数据，仅完整转换成功时生成。不可直接用于增量追加现有规则。
- `cloud_firewall_review`：保留业务连接、原作用范围、顺序和日志意图的中间策略；不是 Cloud Firewall API 请求。DFW scope 与串行防火墙路由不能直接等价，必须设计检查路径。
- `parameter_template_candidates`：去重地址和协议端口候选，不是模板创建请求；没有创建模板或生成模板 ID 引用。
- `group_inventory`：保留原组表达式，辅助标签/组成员映射审阅。

## 输入合同

当前接受整理后的 NSX-T/4.x Policy JSON 快照，结构见 examples。**不直接接受任意原始 API 响应、控制台 CSV 或 NSX-V XML。** 收集器/人工整理必须：

1. 获取所有 Policy、Rules、Groups、Services，处理所有分页；把规则放进 `rules` 数组。
2. 按真实 category、policy 顺序和规则顺序计算全局唯一 `effective_order`；不能只按 rule.sequence_number 排序。
3. 把 policy 继承的 scope、stateful 等字段落实到每条规则；提供明确的 direction 和 ip_protocol。
4. 每个组使用 `/members/ip-addresses` 的完整成员快照填充 members，确认完整后才设 members_complete=true。标签和嵌套表达式保留在 expression，当前不执行表达式。
5. 检查 DFW 排除列表、默认策略、Ethernet/L2 规则、网卡和 IP 发现完整性。不在快照中的规则/资产无法被工具检测，因此必须人工确认快照完整。
6. 服务使用 Policy 的 service_entries；当前仅支持 TCP/UDP 目的端口服务，不支持嵌套服务引用。

成员地址应写成单 IP 或严格 CIDR；不支持 IP 范围字符串。组快照必须带采集时间并在切换前重新采集（工具不会检查时间）。

## 资产与地址变化

mapping.assets 每项表示一个明确的目标保护单元，id 使用稳定 VM/CMDB 标识。old_ips 和 new_ips 按位置一一对应；security_group_id 为事先确定的目标组 ID。

本版要求每个保护单元使用独立安全组，且该组只关联这一个保护单元，以避免共享安全组让权限扩大。SG ID 不能重复。不能把没有映射的机器加入这些组。不输出云上组引用，使用新地址 /32 或 /128，适合作为保守试迁基线；后续角色组聚合需要验证成员的完整有效策略一致。

- `address_map`：显式额外旧地址/CIDR到新地址/CIDR映射；只允许同地址族、同地址集大小，仍需人工确认成员范围。
- `retain_addresses`：明确无需改变的本地或第三方 CIDR白名单。单 IP 也可填入。
- ANY 保留为 IPv4/IPv6 全网，受规则 ip_protocol 过滤；原 ANY 权限也必须审阅。
- 旧资产 IP 重复时拒绝输入，不支持重叠地址空间和多 VPC 身份解析。
- NAT、混合迁移批次、目标服务托管化、合并/拆分资产需要提供正确的可见地址和单独方案，不能自动推断。

## 语义和限制

根据 scope 和方向计算每个目标保护单元的入/出站，仅在本地地址匹配规则端点时生成。部分网卡/地址匹配会阻断。ALLOW→ACCEPT，DROP→DROP，按 effective_order 保持相对顺序。不会为了返回流量增加反向业务规则。

阻断：组不完整、地址无映射、排除匹配、L7 profile、非有状态规则、REJECT、源端口、未知服务、无可映射执行端点、超过配置规则预算。默认预算为每组每方向 200，**这是工具预算，不是对实际账号配额的保证**，部署前核对目标地域及配额。

NSX per-rule logging 只警告，无法在原生 SG 候选中保留。动态标签组转换为成员快照，动态持续同步尚未实现。未知扩展字段没有完整语义检查；输入限于上述受支持子集。

## 推荐实施方式

1. 完整导出并审核资产映射，先做一个依赖明确的应用。
2. 在隔离目标环境创建空的专属安全组，核对缺省行为、实例绑定和全部其他安全组的共同效果。工具不导出实例绑定操作。
3. 审阅计划，确认隐式默认拒绝与原完整策略一致；原默认放行必须作为显式规则进入快照。
4. 使用 SDK/IaC 下发审阅后的规则，保持完整规则列表顺序。工具没有下发、快照或回滚功能，需在执行层实现。
5. 做允许/拒绝的连接矩阵测试，同时检查 DNS、认证、监控、备份、批处理；使用新连接测试。
6. 分批切换，重新采集组成员，撤除过渡规则。角色组聚合、模板创建、Cloud Firewall API 适配应在 PoC 验证后扩展。

## 官方资料

- NSX Rule schema：https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/schemas_Rule.html
- NSX 组、成员和服务导出：https://knowledge.broadcom.com/external/article/429635/exporting-all-nsxt-security-groups-via-a.html
- 腾讯云安全组数据结构：https://cloud.tencent.cn/document/api/215/15824
- 腾讯云安全组和规则创建：https://cloud.tencent.com/document/api/215/43279

这些资料用于字段设计，不代表厂商认证此工具。生产数据尚未验证。

## v0.2：原始输入适配与试运行

新增 `adapt.py`，支持公开 vmware-analyzer 资源 JSON 和 AWS Labs NSX 导出目录。原编译器继续接受规范化快照。详见 TRIAL.md。

公开样例试运行，在本目录执行：

```bash
python3 adapt.py --format analyzer --input public-sample/Example1.json --mapping demo/mapping.json --manifest demo/manifest.json --out demo/normalized.json
python3 migrate.py --snapshot demo/normalized.json --mapping demo/mapping.json --out demo/result
python3 demo/verify.py
```

AWS 导出目录接入：

```bash
python3 adapt.py --format aws-export --input /path/to/extracted-export --mapping /path/to/mapping.json --manifest /path/to/reviewed-manifest.json --out result/normalized.json
python3 migrate.py --snapshot result/normalized.json --mapping /path/to/mapping.json --out result/tencent-plan
```

manifest 模板见 examples/aws-manifest.json。它默认完整性确认值为 false，需要实际检查后填写；不要直接沿用 demo 假设。policy_order 必须列出全部策略，顺序遵循实际 NSX 配置；rule sequence 存在时按 sequence 排序，缺失时需要明确确认数组即有效顺序。group_members 以组 path 为键，提供完整成员 ips 和 complete 标记。

动态成员快照可以包含留在源端的 IP：在 mapping 中显式声明它们不变，或补充实际对端地址映射。没有安全组执行端点的规则会阻断，需要按迁移批次单独处理。

标签原表达式和 tags 导出被保留用于审阅；此版本不解释任意标签表达式，不自动分配云上标签，不持续同步组成员。没有访问 NSX 或腾讯云的实际 API。

## 许可与来源

原创工具代码采用 Apache-2.0 许可。public-sample/Example1.json 来自 np-guard/vmware-analyzer，保留原 Apache-2.0 许可，固定版本和来源见 public-sample/SOURCE.md。AWS Labs 项目仅作为导出文件合同参考，未复制其代码。

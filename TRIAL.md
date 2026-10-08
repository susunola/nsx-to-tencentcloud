# 试运行与 AWS 工具参考记录

## 结果

公开 Example1 JSON → adapt.py → 规范化快照 → migrate.py → 腾讯云候选。
原规则 2 条，组 2 个，目标专属安全组 2 个，展开生成 6 条入/出站规则。
17 个单元/适配测试通过，8 个离线连接检查通过。

| 新连接 | 预期 | 离线检查 |
|---|---|---|
| A → B TCP/445 | 允许 | 通过 |
| A → B TCP/22、443、UDP/445 | 拒绝 | 通过 |
| B → A TCP/445、22、443、UDP/445 | 拒绝 | 通过 |

A、B 原样例无 IP，本次显式补充演示地址映射。stateful=true、IPV4 和数组顺序也是 manifest 中的演示假设。目标安全组 ID 为占位符。检查的是新建连接，未模拟有状态返回包、真实云网络、多个组叠加、NAT 或路由。不是通用语义等价证明。

## AWS 参考

仓库：https://github.com/awslabs/import-export-for-nsx
固定版本：8fffe0e45987fdf490593e9f0cf9875bb5ab1de4
源码：https://github.com/awslabs/import-export-for-nsx/blob/8fffe0e45987fdf490593e9f0cf9875bb5ab1de4/VMCImportExport.py

参考 exportOnPremDFWRule / exportSDDCDFWRule 的文件合同：dfw.json 是策略数组；dfw_details.json 是 policy ID→规则 results 对象；cgw-groups.json 与 services.json 是数组；文件名可配置。

实现了这套目录结构的读取适配，**未运行 AWS 工具连接 NSX**。适配测试使用从公开样例构造的相同结构夹具，不是 AWS 工具实际产生的生产导出。

读取到 cursor 时拒绝转换。审阅该版本的 DFW 导出函数没有看到规则列表分页循环，因此无法单靠导出文件证明完整性；需要核对 counts/分页，并在 manifest 确认。

动态组定义不足以代表完整成员；腾讯云转换补充 group_members。tags.json 仅保留为来源数据，不直接推断腾讯云动态安全组。

AWS 仓库说明导出 ZIP 可提交 AWS Transform 转换为 AWS 原生网络；我们只参考导出合同，腾讯云生成由自己的编译器完成。没有复制 AWS 源码，也没有调用 AWS Transform。

## 限制

仅实现离线适配及腾讯云安全组候选。地址/服务模板和 Cloud Firewall 仍为审阅候选，未实现创建 API、自动下发或回滚。使用真实数据前须核对排除列表、默认规则、组成员、执行范围、目标绑定及账号配额。

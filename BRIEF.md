# upsynth：用户面流量识别与合成

给新会话的开工简报。读完直接按"第一周"开始。

## 目标

输入 5G 用户面抓包（N3 的 GTP-U 或 N6 的裸 IP），识别每条流属于哪个应用或业务类别，
抽出去标识的"业务剖面"，再按剖面合成逼真、Wireshark 能零错误解析的用户面 pcap。
做成 CLI 加 skill 的插件，Claude Code、Codex、DSH、Cursor 都能用。独立项目，不依赖其他仓库。

## 设计依据（别绕开）

1. 用户面基本是 TLS 1.3 和 QUIC，看不到内容。能用的只有 DNS 名、SNI、ALPN、JA4 指纹、
   目的 IP 和 ASN、包长和到达间隔序列、GTP-U 的 TEID 和 QFI。业界 DPI（nDPI、UPF）就是这么做的。
2. 3GPP 的应用识别机制是 PFD（TS 29.251）：域名、URL、五元组描述一个应用。我们的识别规则
   直接导出成 PFD JSON，这是和标准对接的点。
3. 不训练预训练流量模型（ET-BERT 一类的高分已被证明是数据泄漏）。第一版用确定性特征加规则，
   第二版最多加一个 LightGBM。
4. 真实 pcap 不出本机。IP、TEID 等标识在第一步就换成 HMAC 稳定 token，不留 payload。
   剖面文件只含分布，不含单条记录，可以出公司。
5. LLM 的位置：建应用知识库（批量推断域名和 ASN 属于哪个应用）、写解析和生成代码、
   按剖面写每个应用的报文模板。不是分类器。

## 四块

```
pcap -> [ingest] flows.parquet -> [label] labeled.parquet -> [profile] profile.json -> [synth] out.pcap + labels.csv
```

### ingest：解包成流表
- 支持 pcap / pcapng；GTP-U 解封装，保留 TEID、QFI。
- 五元组切流，TCP 看 FIN/RST，UDP/QUIC 120 秒空闲超时。
- 每条流保留：方向、起止时间、包数字节数、前 32 包的带符号长度和间隔序列、
  DNS 名（同 UE 同时间窗反查目的 IP）、SNI、ALPN、JA4、QUIC 版本和 SNI、目的 ASN。
- 脱敏：IP 和 TEID 做 HMAC 映射，不保留 payload。
- 依赖：nfstream（切流和特征，自带 nDPI 弱标签）、scapy（GTP-U 解封装）、dpkt（快速解析备用）、
  pyarrow、pyasn 加离线 ASN 库。

### label：打应用标签
- 规则层：知识库 `kb/apps.yaml`，每条是应用名、业务类别、域名模式、ASN、端口、ALPN。
  命中即标，可导出 PFD JSON。
- 弱标签层：nfstream 的 nDPI 结果。
- 第二版再加 LightGBM 处理无 SNI 的流，训练测试严格按 flow 和时间切分。
- 每条流记录标签来源和置信度。
- 知识库由 agent 从公开数据集的域名清单和搜索扩充，人审。
- 依赖：pydantic 定义 schema。

### profile：抽剖面
- 每个应用：流数占比、持续时间分布、上下行字节分布、分方向包长直方图、间隔分布、
  前 32 包序列聚类中心、并发流数、QFI 分布、端口和 ALPN 分布。
- 每个匿名 UE：活跃时段、应用混合比、会话到达过程参数。
- 全部存直方图或参数化分布，不存原始值。
- 依赖：numpy、scipy、scikit-learn。

### synth：按剖面合成
- 行为层：按剖面采样 UE、会话、流、每条流的长度和间隔序列。第一版经验分布加马尔可夫链。
- 报文层：每个应用一个 Python 模板函数，生成合法报文序列：DNS 查询应答、TCP 握手加
  TLS 1.3 ClientHello（SNI、JA4 匹配）加 ServerHello 加应用数据记录、QUIC Initial 带 SNI。
  按 N3 或 N6 决定是否套 GTP-U。
- 输出 pcap 和 labels.csv（每条流的应用、UE token、起止时间）。
- 唯一的合法性检查：`tshark` 解析零 malformed。不做更多评测。
- 依赖：scapy、dnspython；aioquic 可选。

## 插件形态

```
upsynth/
  pyproject.toml           # 入口 upsynth = upsynth.cli:main（typer）
  upsynth/ cli.py ingest.py label.py profile.py synth/ schemas.py kb/apps.yaml
  skills/upsynth/SKILL.md  # Agent Skills 规范；npx skills add <repo> 可装
  mcp_server.py            # 可选，fastmcp 包四个命令，给不走 bash 的客户端
  tests/ examples/
```

- 每个子命令带 `--json` 和完整 `--help`，agent 读帮助就会用。
- 安装：`uv tool install .` 或 `pipx install .`，Windows 可用。
- SKILL.md 写：何时用、四个命令的顺序和参数、输出在哪、脱敏规则、常见坑
  （先解 GTP-U、DNS 反查要同 UE 时间窗）。
- DSH 是否需要额外插件清单，开工时查文档确认。

## 数据

- 公开：MIRAGE-2019、MIRAGE-AppAct-2024（手机 app 流量带标签）、ISCX VPN-nonVPN、
  Chalmers 2023 5G app 数据集（IEEE DataPort，只有包长和时间）。
- 本地样例：用 Open5GS 加 UERANSIM 跑一份带 GTP-U 的 pcap。
- 真实抓包只在本机用，不进仓库。

## 第一周

1. 建好包结构和依赖，Open5GS 加 UERANSIM 产一份样例 pcap 放 examples/。
2. ingest 跑通：样例进去 flows.parquet 出来，脱敏生效，和 tshark 对账。
3. label 规则层：知识库先 30 个应用，让 agent 从 MIRAGE 域名清单扩到 100 个。
4. synth 先做一个应用（网页浏览）的模板，tshark 零 malformed。
5. SKILL.md 初稿，在 Claude Code 里装上跑完整流程。

## 不做

不碰 payload，不解密，不训预训练模型，不做控制面，不做评测模块，不做 GUI。

## 参考

nfstream 的特征定义；TrafficLLM 仓库里的 Scapy 生成器（看怎么拼包）；
Wireshark-MCP 的 skill 写法；TS 29.251 的 PFD 定义。

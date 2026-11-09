---
name: upsynth
description: 5G 用户面流量识别与合成。读 N3 (GTP-U) 或 N6 抓包，按应用打标签（SNI/DNS/JA4/ASN/端口规则，可导出 3GPP PFD），抽出去标识的业务剖面，再按剖面合成 Wireshark 零错误解析的 pcap 和 labels.csv。Use for 5G user-plane pcap analysis, app identification, traffic profiles, PFD (TS 29.122/29.551), synthetic GTP-U/N6 traffic generation.
---

# upsynth

四个命令，按顺序用。每个命令都有 `--help` 和 `--json`；在 agent 里一律加 `--json`，读返回的 JSON。

```
upsynth ingest  capture.pcap   -o flows.parquet     # 解包切流，脱敏
upsynth label   flows.parquet  -o labeled.parquet   # 打应用标签（--pfd pfd.json 同时导出 PFD）
upsynth profile labeled.parquet -o profile.json     # 抽剖面，只有分布
upsynth synth   profile.json   -o out.pcap          # 合成，另写 out.labels.csv，自动跑 tshark 检查
```

没装命令时：在仓库里 `uv tool install .` 或 `pipx install .`；临时用 `uvx --from <仓库路径> upsynth ...`。

## 什么时候用

- 用户给了 5G 用户面抓包（pcap/pcapng），想知道里面是哪些应用、各占多少。
- 要把识别规则交给 UPF/NEF：`upsynth label ... --pfd pfd.json` 或 `upsynth kb --pfd pfd.json`。
- 要一份逼真、不含真实用户数据的测试流量：先 profile 再 synth。
- 只有剖面文件（别人给的 profile.json），也能直接 synth。

## 各步要点

ingest
- N3 抓包里的 GTP-U（UDP 2152）会自动解开，TEID、QFI 保留；方向优先看 PDU Session Container 的 UL/DL。
- 每条流有：起止时间、上下行包数字节数、前 32 包带符号长度（上行正、下行负）和间隔、DNS 名、SNI、ALPN、JA4、QUIC 版本、HTTP Host。
- ASN 要离线库：`--asn-db ip2asn-v4.tsv.gz`（iptoasn.com 下载）或环境变量 `UPSYNTH_ASN_DB`。没有就是空值，不影响别的。
- 结果里 `with_sni`、`with_dns_name` 很低时，多半是抓包从中途开始（没抓到握手和 DNS）。

label
- 规则顺序：SNI > HTTP Host > DNS 名 > JA4 > ASN > nDPI > 端口。域名按最长后缀匹配。
- 返回的 `unknown_names` 是没认出来的域名，按次数排序。扩知识库就从这里开始。

profile
- `--min-flows`（默认 5）和 `--min-ues`（默认 1）以下的应用并进 `other`。剖面要出公司前，把 `--min-ues` 调到 3 以上。

synth
- `--ues`、`--duration`（秒）、`--iface n3|n6`、`--seed`、`--app youtube`（可重复）。
- 返回里的 `check.malformed` 必须是 0；不是 0 时退出码为 2，`check.examples` 给出帧号和协议栈。
- `ports_remapped` 不为空，说明有不透明流原端口上挂着别的 Wireshark 解析器，已换到空闲端口。
- 服务器地址在 198.18.0.0/15 和 2001:db8::/32，不指向真实主机。

识别业务（点播 / 直播 / 短视频 / 其它，要装 `upsynth[ml]`）
- `upsynth train --data 地区=labeled.parquet[,标签] --holdout app --holdout region -o model.json`。标签是业务名（整份抓包就是这件事），或时间表 CSV（`start,end,service[,app]`，本地时间或 Unix 秒）。不给标签时用知识库类别做弱标签。
- 手机上抓的包 ingest 时加 `--ue phoneA`，整份算一台手机。
- `upsynth classify labeled.parquet --model model.json -o services.csv [--truth 标签]`。
- 看 `evaluation` 里留出 App、留出地区的 `macro_f1`，不看随机切分。详细做法在仓库的 `docs/PHONE.md`。

## 脱敏规则（必须遵守）

- 真实抓包和 flows.parquet、labeled.parquet 只留在本机，不上传、不贴进对话、不提交到仓库。
- IP 和 TEID 在 ingest 第一步就换成 HMAC token，密钥在 `~/.upsynth/key`（或 `--key`、`UPSYNTH_KEY`）。不要把密钥发出去。
- 不保留 payload；profile.json 只有直方图、占比、聚类中心，可以出公司。
- 给用户看结果时，用应用名和统计数，不要列 token 或单条流。

## 扩知识库

知识库在 `upsynth/kb/apps.yaml`，每条：`name`、`category`、`domains`、`asns`、`ports`、`alpn`、`ja4`。

1. 跑 `upsynth label flows.parquet --json`，看 `unknown_names`。
2. 判断每个域名属于哪个应用（查公开资料）。拿不准的不加。
3. ASN 只写应用独占的网络，云厂商和 CDN 的 ASN 不要写到某个应用下。
4. 改完跑 `upsynth kb --json` 检查（重复域名、重复 ASN、类别拼写都会报错），再 `upsynth kb --find <域名>` 抽查。
5. 改动给人审过再合并。

## 常见坑

- 先解 GTP-U 再切流：ingest 自己会做，不要先用别的工具去掉外层再喂进来（会丢 TEID、QFI 和方向）。
- DNS 反查只认同一个 UE、同一时间窗（`--dns-window`，默认 600 秒）。别的 UE 的 DNS 答案不会用来命名这条流。
- QUIC 的 SNI 要抓到客户端第一个 Initial；中途开始的 QUIC 流只有端口信息。
- 抓包是 Linux cooked（any 接口）、raw IP、以太网都可以；IP 分片的后续片会跳过，结果里 `skipped.fragments` 有计数。
- synth 输出要验证就看 `check`；本机没有 tshark 时 `check.ok` 是 null，装 Wireshark 或设 `UPSYNTH_TSHARK`。

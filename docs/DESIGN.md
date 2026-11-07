# upsynth 设计

四步，每步一个模块，一个命令。中间文件都是普通格式（parquet、JSON、CSV），可以单独检查。

```
capture.pcap --ingest--> flows.parquet --label--> labeled.parquet --profile--> profile.json --synth--> out.pcap + labels.csv
```

| 模块 | 文件 | 输入 | 输出 |
|---|---|---|---|
| ingest | `upsynth/ingest.py`、`pcapio.py`、`tls.py`、`quic.py`、`anon.py`、`asn.py` | pcap / pcapng | flows.parquet |
| label | `upsynth/label.py`、`kb/apps.yaml` | flows.parquet | labeled.parquet，可选 PFD JSON |
| profile | `upsynth/profile.py` | labeled.parquet | profile.json |
| synth | `upsynth/synth/` | profile.json | pcap、labels.csv、tshark 检查结果 |

数据格式都在 `upsynth/schemas.py`：`FLOW_SCHEMA`、`LABELED_SCHEMA`、`KnowledgeBase`、`Profile`。

## ingest

读文件：dpkt 读 pcap 和 pcapng，链路层支持以太网（含 VLAN、MPLS）、raw IP、Linux cooked v1/v2、BSD loopback。IP、UDP、TCP、GTP-U 自己解，只取要用的字段。

GTP-U：UDP 2152 的 G-PDU 解开取内层 IP，保留 TEID。扩展头链里的 PDU Session Container（类型 0x85，TS 38.415）给出 QFI 和方向（PDU type 1 上行，0 下行）。回声、End Marker 这类信令计入 `skipped.gtpu_signalling`。

切流：双向五元组。TCP 在 RST 或双方 FIN 后结束（之后 2 秒内的零散包算同一条），同一五元组上出现新的 SYN 也会切开。UDP 和 QUIC 空闲 120 秒结束。TCP 也有 600 秒空闲上限，防止漏掉 FIN 的流一直挂着。

谁是 UE：有 PDU Session Container 时按它；否则 TCP 看 SYN；再看哪一侧是常见服务端口、哪一侧是私网地址；都分不出时，第一个包的发送方算 UE。

每条流记下：
- 起止时间、上下行包数和字节数（内层 IP 长度）。
- 前 32 个包的带符号长度（上行正、下行负）和到达间隔（毫秒，第一个是 0）。
- DNS 名：同一个 UE 在时间窗内（默认 600 秒）的 DNS 应答里，哪个查询名解析到了这条流的服务器 IP。别的 UE 的应答不用。
- TLS：把客户端前 12 个数据段按序号拼起来，跨记录、跨段重组 ClientHello，取 SNI、ALPN 列表、JA4 和 JA4 原始串。
- QUIC：用客户端第一个 DCID 推导 Initial 密钥（RFC 9001，v1 和 v2），解密前 6 个客户端数据报里的 Initial，按偏移拼 CRYPTO 帧，再解析 ClientHello。遇到 Retry 后换新 DCID 的情况也能解。
- 明文 HTTP 的 Host。
- 服务器 ASN（离线库，可选）。

脱敏：IP 和 TEID 用 HMAC-SHA256 换成 16 位十六进制 token，写文件之前就换掉。ASN 和 DNS 反查在内存里用原始地址做完。不保留 payload。密钥来自 `--key`、`UPSYNTH_KEY`，或第一次运行时生成的 `~/.upsynth/key`，同一密钥下 token 稳定，同一个 UE 的流能关联起来。

JA4 按 FoxIO 规范：`t13d1516h2_<排序后加密套件的 sha256 前 12 位>_<排序后扩展（去掉 SNI 和 ALPN）加签名算法的 sha256 前 12 位>`，忽略 GREASE。测试里用规范中的 Chrome 例子核对。

## label

知识库 `upsynth/kb/apps.yaml`，185 个应用，每条有名字、类别、域名、ASN、端口、ALPN、JA4，可选 synth 模板名。来源是 MIRAGE-2019 / MIRAGE-AppAct-2024 的应用清单、厂商的网络需求页、nDPI 的主机名表，加上国内常用应用。

规则顺序，先命中先用：

| 来源 | 置信度 |
|---|---|
| SNI | 0.95 |
| HTTP Host | 0.9 |
| DNS 名 | 0.85 |
| JA4 | 0.75 |
| ASN | 0.6 |
| nDPI（ingest 加了 `--ndpi` 时） | 0.5 |
| 端口 | 0.4 |

nDPI 给的名字对不上知识库里的应用时，标成 `ndpi:<名字>`，放在端口规则之后。

例外：53、123、853 端口先按端口判（DNS 流里的名字是被查的域名，不是这条流的应用）。

域名匹配：写 `example.com` 就匹配它和所有子域名，所有应用里取最长的后缀。所以 `mail.google.com` 归 gmail，`fonts.gstatic.com` 归 google。带 `*` 的通配和 `re:` 正则写给 CDN 上的某个应用（如 `*spotify*.akamaized.net`），优先于后缀。ASN 只写应用独占的网络。重复的域名或 ASN、写错的类别，加载时就报错（`upsynth kb` 检查）。

PFD 导出（`--pfd`）：按 TS 29.122 PfdManagement 的 `pfdDatas` 结构，每个应用一个 PfdData，`externalAppId` 是应用名。域名放进一个 PFD 的 `domainNames`（同时写 `x.com` 和 `*.x.com`），`dnProtocol` 是 TLS_SNI（TS 29.551 PfdContent）；端口写成 IPFilterRule 的 `flowDescriptions`，如 `permit out 17 from any 8801-8810 to assigned`。ASN 和 JA4 在 PFD 里没有对应字段，不导出。

## profile

DNS 流不进应用列表，只记一个比例 `dns_ratio`（每条非 DNS 流对应多少次 DNS），synth 用它决定流前面要不要先查 DNS。

每个应用：
- 流数占比；传输方式和服务端口的联合分布（`endpoints`，如 `tls_tcp/443`、`udp/123`，分开存会合成出 `tcp/123` 这种组合）；ALPN、域名、客户端栈（JA4 原始串）、QFI 的分布。
- 持续时间、总包数、上下行包数、上下行字节数的对数直方图；分方向包长直方图（ACK、握手、满 MTU 附近 4 字节一档，中间 32 字节一档）；到达间隔对数直方图。
- 前 32 包序列的 k-means 聚类（最多 8 个）。每个簇存中心，也存每个位置上“方向加包长档”的分布和“流已结束”的比例。只存中心不够：同一位置有时是满载数据包、有时是 52 字节的 ACK，平均出来是两边都不像的中间值。不到 3 条流的簇并进最近的大簇，没有哪个簇只代表一条流。
- 包级马尔可夫链（状态是方向加包长档），用在第 32 包以后的方向。
- 超过 32 包的流，第 32 包之后平均每包多少字节（分方向，每条流一个值）。前 32 包多是握手，大流后面是满载包加 ACK，单靠前 32 包学不到。
- 同一 UE 同一应用的并发流数。

每个 UE（重新编号成 ue1、ue2……，不出现 token）：24 小时活跃分布、应用混合比、会话内流到达间隔、每段会话的流数、每小时会话数。会话按 300 秒空闲切分。还有一张“上一个应用到下一个应用”的转移表。

隐私：流数少于 `--min-flows`（默认 5）或 UE 数少于 `--min-ues`（默认 1）的应用并进 `other`。`other` 不保留域名。域名只保留知识库认出来的（公开应用的服务器名）。没有单条流的记录。

## synth

行为层（`synth/behavior.py`）：每个 UE 套一个剖面里的 UE 画像。会话里按画像的流间隔排出流的开始时间；下一个应用 70% 按转移表、其余按应用混合比；同时开几条按并发分布。每条流从应用的分布里取端点（传输方式加端口）、域名、客户端栈、ALPN、QFI。包序列：按权重选一个簇，逐个位置抽“方向加包长档”，再在应用的包长直方图里限定到这一档取具体长度；簇里抽到“结束”就是短流。走完 32 个位置还没结束的，从总包数分布大于 32 的部分取长度，后面的方向走马尔可夫链，包长按尾段平均值 A 取：以概率 q 取满载、否则取 ACK 大小，q 让平均值等于 A。间隔从间隔直方图采样，长流再按持续时间缩放。

报文层（`synth/templates.py`、`synth/protocols.py`）：

| 模板 | 内容 |
|---|---|
| tls_tcp | 三次握手；TLS ClientHello 按 JA4 原始串重建，JA4 与剖面一致，SNI 和 ALPN 来自剖面；TLS 1.3 的 ServerHello、ChangeCipherSpec、应用数据记录（TLS 1.2 栈走会话恢复握手）；FIN 收尾 |
| web_browsing | 网页、新闻、搜索、旅行、购物类默认用它：先 DNS，HTTP/2 over TLS 1.3，剖面没有序列时用内置的页面加载形态 |
| quic | 真正加密的 QUIC v1 Initial（Wireshark 能解出 ClientHello 和 SNI），服务器 Initial 带 ServerHello，之后是 Handshake 包和 1-RTT 短头包 |
| tcp | 按端口生成明文协议：HTTP/1.1、MQTT、SIP、RTMP；其他端口是不透明字节 |
| udp | 按端口生成：NTP、DNS、STUN 加 RTP（ICE）、WireGuard、OpenVPN、IKEv2、ESP；会议和语音类用 RTP 形态；其他是不透明字节 |

TCP 序号、确认号、时间戳选项、TLS 记录长度、HTTP 的 Content-Length、MQTT 的剩余长度都对得上。每个方向连续的数据算一段，段的内容先生成好，再按剖面的包长切成 TCP 段，所以重组后的字节流是完整的。

封装：N3 是 gNB（10.10.0.11）和 UPF（10.10.0.7）之间的 GTP-U，带 PDU Session Container（上行 PDU type 1、下行 0、QFI），每个 UE 一对上下行 TEID；N6 是裸 IP。UE 地址 10.45.0.0/16（Open5GS 默认地址池）。服务器地址按域名哈希到 198.18.0.0/15（IPv6 是 2001:db8::/32），DNS 服务器默认 8.8.8.8。默认内层 MTU：N3 1400，N6 1500。

检查（`synth/check.py`）：`tshark -r out.pcap` 逐帧看 `_ws.malformed` 和 expert 错误级别。`_ws.malformed` 包括 Note 级别、归在 Malformed 组下的提示，按最严的口径算。

换端口：有些端口 Wireshark 绑了自己的解析器（`tshark -G decodes`，约 935 个）。不透明字节或别的协议落在这些端口上，会被当成那个协议解析，报 malformed。synth 对这种流换一个没有注册的端口（同一个原端口总是换到同一个新端口），结果里 `ports_remapped` 会列出来。注册表随包带一份 Wireshark 4.6.9 的快照（`synth/wireshark_ports.tsv`），本机有 tshark 时再加上它的列表。自带编解码器的端口、TLS 端口、UDP 443 上的 QUIC 不换。

## 和简报不一样的地方

| 简报 | 现在 | 原因 |
|---|---|---|
| nfstream 切流和取特征 | 自己切流（dpkt），nfstream 做成可选的 `--ndpi` 弱标签 | nfstream 要编译好的 nDPI，新版 Python 和 Windows 上常常没有现成的包；简报要的切流规则、QUIC Initial 解密、同 UE 的 DNS 窗口，自己做更直接 |
| scapy 解 GTP-U、拼包，dnspython | 手写字节 | 只用到很少的字段；手写的快、结果可复现，少两个依赖；合法性由 tshark 检查 |
| pyasn | 纯 Python 读 pyasn 的 ipasn 文件、iptoasn 的 TSV 或 CSV | pyasn 要 C 编译，Windows 上麻烦 |
| scikit-learn、scipy | numpy 写的 k-means++ 和直方图 | 只用到这两样，省掉两个大依赖 |
| 四个命令 | 另加 `upsynth kb`（检查知识库、查域名、导出 PFD） | agent 扩知识库后要能自查 |
| Minecraft Bedrock（RakNet，19132） | 换端口 | Wireshark 的 MCPE 解析器要看到登录和加密协商才能解析，单独造的游戏包过不了 |
| 第二版的 LightGBM | 没做 | 简报里就是第二版 |

## 拿真实样例对一下

`examples/open5gs_n3.pcap` 的完整抓包（448 条非 DNS 流）出剖面，再合成 10 个 UE、300 秒，合成结果重新 ingest 后比较：

| | 真实 | 合成 |
|---|---|---|
| 持续时间中位数（秒） | 0.23 | 0.26 |
| 上行字节中位数 | 2091 | 2041 |
| 下行字节中位数 | 18313 | 18043 |
| 包数中位数 | 41.5 | 39 |
| 前 32 包上行包长中位数 | 52 | 52 |
| 前 32 包下行包长中位数 | 1278 | 1234 |
| 下行包占比 | 0.57 | 0.56 |
| 下行字节 P90 | 625 KB | 278 KB |

大流的尾部偏小：真实样例只有 448 条流，P90 只由四十来条流决定，而且包数和字节数是分开存的。简报说不做评测模块，这里只是一次核对。

## 装进 agent

- Claude Code：仓库根目录有 `.claude-plugin/plugin.json` 和 `marketplace.json`，skill 在默认的 `skills/` 下。
- DSH：skill 就是 `<名字>/SKILL.md` 目录，放进 `~/.agents/skills` 或 `~/.dsh/skills` 会被自动发现，不需要额外的插件清单；`dsh plugin add` 只装代码插件。
- Codex、Cursor：复制或链接 `skills/upsynth` 到各自的 skills 目录。
- 验证过一次：Codex 装上 skill 后，只给一句中文任务，它自己读 SKILL.md 和 `--help`，跑完 ingest、label（带 PFD）、profile、synth，报告 tshark 零 malformed。

## 测试

`pytest`：JA4 对照 FoxIO 例子；QUIC 密钥对照 RFC 9001 附录 A；ingest 的流数、GTP-U 字段、脱敏（文件里搜不到原始地址）、DNS 窗口、空闲超时、ASN；label 的规则顺序和最长后缀；PFD 结构；profile 里没有 token；同一 seed 生成的 pcap 字节完全相同；synth 的输出再 ingest 回来，SNI 和 JA4 和 labels.csv 一致；tshark 对账（SNI 集合、TCP 会话数）；tshark 自己算的 JA4 和 labels.csv 一致；知识库所有端口规则、所有编解码器端口、随机抽 150 个注册端口，tshark 零 malformed；真实样例的 N3 和 N6 两个视角得到同一批流，SNI 和 JA4（wget、aioquic 的真实指纹）和 Wireshark 一致，标签覆盖 95% 以上，由真实剖面合成的流量零 malformed。

# 样例

| 文件 | 内容 |
|---|---|
| `open5gs_n3.pcap` | N3 抓包：Open5GS + UERANSIM，一个 UE 浏览约 140 秒。gNB 和 UPF 之间的 GTP-U，带 PDU Session Container（QFI 1） |
| `open5gs_n6.pcap` | 同一段时间 UPF 的 ogstun 口（N6 侧，raw IP），和 N3 是同一批流 |
| `open5gs_profile.json` | 用完整抓包（没裁剪）跑 ingest、label、profile 得到的剖面 |
| `open5gs/` | 产生这些文件的脚本 |

两个 pcap 都裁剪过：每条流只留前 16 帧（`open5gs/trim.py`），原始抓包有 160 MB。帧没有改动，握手、DNS、GTP-U 头都在。600 条流（含 152 次 DNS 查询），438 条有 SNI，448 条能反查到 DNS 名。

流量是实验室里的 UE 访问公开网站（百度、京东、B 站、知乎、网易等），没有任何人的真实数据。客户端是 wget 和 aioquic，所以 JA4 是它们的指纹，不是手机浏览器的。

当时的网络挡掉了 UDP 443，HTTP/3 请求只发出了 Initial，没有回包，所以抓包里只有 2 条单向的 QUIC 流。QUIC 合成模板用自带的确定性样例验证（`upsynth.sample`，Wireshark 能解开 Initial 读到 SNI）。

## 跑一遍

```
upsynth ingest  examples/open5gs_n3.pcap -o flows.parquet
upsynth label   flows.parquet -o labeled.parquet
upsynth synth   examples/open5gs_profile.json -o out.pcap --ues 10 --duration 300
```

## 自己产一份

步骤、国内镜像、虚拟机的启停、带动作记录的抓法，都在 `docs/LAB.md`。脚本在 `open5gs/`：`setup.sh` 装核心网，`run.sh` 抓包，`traffic.sh` 是默认的网页访问，`human_bilibili.py` 是带动作记录的 B 站操作。

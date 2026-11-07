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

需要一台 Ubuntu 24.04（真机或虚拟机，arm64 和 amd64 都行），root 权限。macOS 上可以用 lima：

```
limactl start --name=fivegc --cpus=4 --memory=4 --vm-type=vz template:ubuntu-24.04
limactl shell fivegc -- sudo bash examples/open5gs/setup.sh       # 装 Open5GS、MongoDB、UERANSIM，加测试用户
limactl shell fivegc -- sudo env DURATION=150 bash examples/open5gs/run.sh
limactl copy fivegc:/tmp/upsynth-capture/n3.pcap .
```

国内网络可以给 setup.sh 加 `UBUNTU_MIRROR=http://mirrors.ustc.edu.cn/ubuntu-ports`（amd64 用 `.../ubuntu`）。

`run.sh` 起 gNB 和 UE，把 UE 的 `uesimtun0` 挪进单独的网络命名空间，默认路由和 DNS（223.5.5.5）都走 5G，所以 DNS、HTTPS、QUIC、NTP 全部经过 N3。抓包在回环口（`udp port 2152`）和 ogstun。UE 做什么在 `traffic.sh` 里改。

用户的 IMSI、K、OPc 和 UERANSIM 自带的 `config/open5gs-ue.yaml` 一致，Open5GS 用默认配置（PLMN 999-70，UE 地址池 10.45.0.0/16）。

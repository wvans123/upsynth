# 实验室：Open5GS + UERANSIM

一台 Ubuntu 24.04 上跑 5G 核心网和模拟手机，让流量穿过 N3（GTP-U），同时记下人在做什么。用来验证 upsynth 的管道，也用来产带动作真值的抓包。

这不是真手机。抖音、快手的网页会拦自动化浏览器；B 站页面能打开，但播放器经常并不真正把视频拉下来。要识别真实 App、要换地区还能用，训练数据得来自真机抓包。实验室只保证方法能跑通。

## 要什么

- Ubuntu 24.04，arm64 或 amd64，root，能上网。内存 4 GB，磁盘 20 GB。
- macOS 上用 lima 起这台 Ubuntu。Windows 上用 Hyper-V 或别的完整虚拟机，不要用 WSL（Open5GS 要 systemd）。
- 宿主机装好 upsynth 和 tshark，抓包拷出来再分析。

## macOS：起虚拟机

```
brew install lima
limactl start --name=fivegc --cpus=4 --memory=4 --disk=20 --vm-type=vz --tty=false template:ubuntu-24.04
```

Apple 芯片用 `--vm-type=vz`。Intel Mac 去掉这一项，lima 会用 qemu。

lima 把你的主目录挂进虚拟机，路径不变。仓库要放在主目录下，比如 `~/upsynth`，虚拟机里才找得到。

第一次开机时系统自己在跑 apt，锁还没放。等它结束再装：

```
limactl shell fivegc -- bash -c 'sudo cloud-init status --wait; while sudo fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 3; done; echo free'
```

## 安装核心网

在虚拟机里，用 root：

```
limactl shell fivegc -- sudo -E env UBUNTU_MIRROR=http://mirrors.ustc.edu.cn/ubuntu-ports \
  bash ~/upsynth/examples/open5gs/setup.sh
```

amd64 的镜像地址是 `http://mirrors.ustc.edu.cn/ubuntu`，不是 `ubuntu-ports`。国外网络不用设 `UBUNTU_MIRROR`。

`setup.sh` 做这些事：换成可选的 apt 镜像；装编译工具和 tcpdump；装 MongoDB 8 和 Open5GS（PPA `open5gs/latest`）；从上游仓库拿 `open5gs-dbctl`（安装包里没有这个命令），写入测试用户，IMSI `999700000000001`，和 UERANSIM 自带的 `config/open5gs-ue.yaml` 一致；打开转发，给 `10.45.0.0/16` 做 NAT；编译 UERANSIM 到 `/opt/UERANSIM`；装 aioquic，给默认的网页流量用。

UERANSIM 编译要几分钟。结束时打印 `setup done`。

不是 lima 的机器，直接 `sudo bash examples/open5gs/setup.sh`。

## 抓一份普通流量

```
limactl shell fivegc -- sudo env DURATION=150 bash ~/upsynth/examples/open5gs/run.sh
limactl copy fivegc:/tmp/upsynth-capture/n3.pcap .
limactl copy fivegc:/tmp/upsynth-capture/n6.pcap .
```

`run.sh` 每次都会重新打开 IP 转发和 NAT（重启虚拟机后这两项会丢），再拉起 gNB 和 UE。UE 拿到 `10.45.0.2` 后，脚本把 `uesimtun0` 挪进网络命名空间 `ue`，默认路由和 DNS（223.5.5.5）都走 5G。UE 里做的事是 `traffic.sh`：用 wget 打开一批网页，再发 NTP。

N3 在回环口抓 `udp port 2152`，N6 在 `ogstun` 上抓。结束时打印 `captures in /tmp/upsynth-capture`。

UE 进程的日志在同目录的 `ue.log`。注册成功会有 `PDU Session establishment is successful`。看到 `FIVEG_SERVICES_NOT_ALLOWED`，是数据库里没有这个用户，重跑 `setup.sh`。

## 抓带动作记录的流量

动作脚本会打开 B 站手机版，轮流做三件事：看点播、进直播间、快速滑过短视频。每个动作写一行 CSV：开始时间、结束时间、应用、动作、业务（`vod` / `live` / `short_video` / `other`）。

先在虚拟机里装浏览器。apt 锁要空着：

```
limactl shell fivegc -- sudo -E bash -c 'python3 -m venv /opt/pwvenv && /opt/pwvenv/bin/pip install -q playwright && /opt/pwvenv/bin/playwright install --with-deps chromium'
```

浏览器装在登录用户的缓存里，root 找不到。跑的时候带上 `PLAYWRIGHT_BROWSERS_PATH`。先等隧道起来 3 秒，避免第一个请求报 `ERR_NETWORK_CHANGED`：

```
limactl shell fivegc -- sudo env DURATION=600 OUT=/tmp/upsynth-actions \
  TRAFFIC="sleep 3; PLAYWRIGHT_BROWSERS_PATH=/home/lima/.cache/ms-playwright /opt/pwvenv/bin/python ~/upsynth/examples/open5gs/human_bilibili.py --out /tmp/upsynth-actions/actions.csv --duration 600 --seed 11" \
  bash ~/upsynth/examples/open5gs/run.sh
```

lima 里的用户名不一定是 `lima`。安装浏览器时看最后一行打印的路径，把上面的 `PLAYWRIGHT_BROWSERS_PATH` 换成那个目录。

拷出来：

```
limactl copy fivegc:/tmp/upsynth-actions/n3.pcap .
limactl copy fivegc:/tmp/upsynth-actions/actions.csv .
```

接着在宿主机上：

```
upsynth ingest  n3.pcap -o flows.parquet
upsynth label   flows.parquet -o labeled.parquet
upsynth profile labeled.parquet -o profile.json --actions actions.csv
upsynth actions profile.json
upsynth synth   profile.json -o out.pcap --mode actions --ues 10 --duration 600
```

`--script` 播放一份动作剧本，格式见 `upsynth actions` 打出来的例子，`examples/scripts/personas.json` 是一份人设剧本。剧本里的动作名必须是这个剖面里有的。

## 停和删

```
limactl stop fivegc      # 关机，磁盘还在 ~/.lima/fivegc，约占 20 GB
limactl start fivegc     # 再开。转发和 NAT 由 run.sh 重新加上
limactl delete fivegc    # 连磁盘一起删
```

虚拟机开着时占 4 GB 内存。不用就停。

## 踩过的坑

- 宿主机开了 HTTP 代理时，lima 会把代理塞进虚拟机的环境变量。UE 的流量必须去掉这些变量，否则请求不走 5G。`run.sh` 已经去掉。
- 虚拟机里 `ping` 不通外网，不代表 HTTPS 不通。先用 `ip netns exec ue curl -I https://www.baidu.com` 看。
- 有的网络挡住 UDP 443。HTTP/3 只能发出去，没有回包。
- 动作脚本里的“短视频”是快速划过 B 站视频，不是抖音。抖音网页对自动化浏览器直接给验证码；快手网页版加载不出视频。
- 播放器的进度条在走，不代表网上有视频字节。看抓包里 `bilivideo.com`、`smtcdns.net` 这些域名的下行量。没有的话，这份抓包不能拿来训练“点播还是直播”。

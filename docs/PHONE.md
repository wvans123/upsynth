# 用真手机和现网数据训练“点播 / 直播 / 短视频”识别

## 抓包是什么

手机上网时，每一次收发都是一个个数据包。抓包就是把这些包按时间记下来，存成一个 `.pcap` 文件。

视频内容是加密的，我们打不开，也不需要打开。识别靠的是每个包的时间、大小、方向，以及握手时露出来的域名。点播会先猛下一阵再停，直播每一两秒均匀地拉一点，短视频跟着手指一下一下地来。从这些节奏就能分出业务。

文件里会有手机的 IP 和访问过的网站。`upsynth ingest` 第一步就把 IP 换成编号，不留内容。原始 `.pcap` 只放在自己电脑上，不要上传、不要发群。

## 两种抓法

### 安卓：手机上装 PCAPdroid（推荐）

PCAPdroid 是开源免费的应用，不用 root。它在手机上开一个本地“VPN”，所有流量从它身边过一遍，记下来再放走。数据还是走你的 5G 或 Wi-Fi，不经过别的服务器。

1. 从应用商店、F-Droid 或 GitHub（emanuele-f/PCAPdroid）安装。
2. 打开后在“导出方式”（Dump mode）里选 PCAP 文件。目标应用选“全部”就行。不要打开 TLS 解密。
3. 点开始，系统会问是否允许建立 VPN，选允许。手机上原来开着别的 VPN 的话，要先关掉。
4. 去做一件事，比如刷抖音 10 分钟。
5. 回到 PCAPdroid 点停止，文件存进手机的下载目录。
6. 用数据线拷到电脑。文件名写清楚做了什么，比如 `0611_douyin_feed_5g.pcap`。

### iPhone：数据线连 Mac

Mac 上要装 Xcode。iPhone 第一次连 Mac 时，要在手机上点“信任此电脑”。

```
xcrun xctrace list devices            # 找到 iPhone 后面括号里的一长串编号（UDID）
rvictl -s <UDID>                      # 多出一个网卡 rvi0；提示权限不足就在前面加 sudo
sudo tcpdump -i rvi0 -w 0611_bilibili_vod_5g.pcap
# 手机上做事，做完回到终端按 Ctrl+C
rvictl -x <UDID>
```

这样抓到的是 iPhone 本身的流量，5G 和 Wi-Fi 都在里面。

## 怎么录，才能直接拿来训练

最省事的做法：一个文件只做一件事，录 10 分钟左右，用文件名记下是什么。

| 业务 | 怎么做 | 标签 |
|---|---|---|
| 短视频 | 抖音、快手、视频号的推荐流，一直往下划 | `short_video` |
| 点播 | B 站、腾讯视频、爱奇艺、优酷，看一个长视频或剧集 | `vod` |
| 直播 | 抖音、B 站、快手、虎牙、斗鱼的直播间，待着看 | `live` |
| 其它 | 刷微博、看新闻、聊天、逛淘宝 | `other` |

要注意的几点：

- 录的时候别切去做别的事。微信消息之类的后台流量没关系，训练时会被排除。
- 每一类至少用 3 个不同的 App。这样能检查模型学会的是“直播”，而不是“虎牙”。
- 同一件事多换几种网络：5G、4G、Wi-Fi，信号好和信号差的地方，白天和晚上。
- 起步每类录 30 到 60 分钟，四类加起来 2 到 4 小时。

也可以长时间连续录，另外手写一张时间表（CSV，用 Excel 存成 UTF-8 的 CSV 也行）：

```
start,end,service,app
2026-11-10 14:00:00,2026-11-10 14:10:00,short_video,douyin
2026-11-10 14:12:00,2026-11-10 14:25:00,vod,bilibili
2026-11-10 14:26:00,2026-11-10 14:40:00,live,huya
```

时间是电脑上的本地时间。手机和电脑都设成自动对时。`app` 列可以不填；填的话用知识库里的名字（`douyin`、`kuaishou`、`bilibili`、`tencent_video`、`iqiyi`、`youku`、`huya`、`douyu`……），不确定时用 `upsynth kb --find 域名` 查。

## 在电脑上处理

每个文件先切流、打标签。`--ue` 告诉它这整个文件是一台手机，这样同一部手机的 IPv4、IPv6 和中途换的地址都算一台：

```
upsynth ingest 0611_douyin_feed_5g.pcap --ue phoneA -o douyin1.parquet
upsynth label  douyin1.parquet -o douyin1.labeled.parquet
```

训练时每个文件一条 `--data`，写成 `地区=文件,标签`。标签可以是业务名（整份文件就是这件事），也可以是上面那张时间表：

```
upsynth train -o model.json --holdout app --holdout region \
  --data shanghai=douyin1.labeled.parquet,short_video \
  --data shanghai=bili1.labeled.parquet,vod \
  --data shanghai=huya1.labeled.parquet,live \
  --data shanghai=weibo1.labeled.parquet,other \
  --data jiangsu=long1.labeled.parquet,times_jiangsu.csv
```

“地区”就是你给这批数据起的分组名，可以是城市，也可以是城市加运营商，比如 `shanghai-cmcc`。

`--holdout app` 每次留出一个 App 不训练，拿来考试。`--holdout region` 每次留出一个地区。输出里的 `macro_f1` 越接近 1 越好，`per_group` 能看出是哪个 App 或地区拖了后腿。

拿训练好的模型去认一份新抓包：

```
upsynth classify new.labeled.parquet --model model.json -o services.csv
upsynth classify new.labeled.parquet --model model.json --truth live    # 已知答案时顺便打分
```

## 判断这条路通没通

1. 只有一个地区时，先看 `--holdout app`。不同 App 之间也能认出来，说明学到的是业务，不是某个 App。
2. 第二个地区的数据到手后看 `--holdout region`。用上海训练、拿江苏考试，分数不明显下降，才算能泛化。
3. 没条件去外地时，可以先换移动、联通、电信的卡来录，三家的 CDN 不一样，可以当成第一轮的“换地区”。

## 现网数据

运营商的 N3（基站和 UPF 之间）或 N6（UPF 出口）抓包，`upsynth ingest` 都能直接读。N3 的 GTP-U 会自动拆开，不用加 `--ue`，每个用户按自己的地址分开。

规矩：

- 先确认公司允许用这份数据。处理放在内网机器上，原始抓包不拷出来。
- ingest 第一步就把 IP 和 TEID 换成编号。密钥在那台机器的 `~/.upsynth/key`，不要外发。
- 能带出来的只有模型、剖面（`profile.json`）和统计结果，不带单条流。

现网数据里的用户在干什么，没人知道，有两个用法：

- 直接拿来考试。用真机数据训练好的模型去认现网流量，看各业务的占比合不合理，再抽查几个用户。
- 拿来当训练数据，最好的办法是把自己的测试手机接进被抓的那张网。录的同时记时间表，表里多加一列 `ue_ip`，填测试手机在那段时间的 IP。只有这台手机的流量会拿到标签，其他用户不受影响。训练要用 ingest 时同一把密钥（同一台机器，或者 `--key` 传同一个值）。

没有时间表时，`upsynth train` 会退回用知识库的类别当弱标签：虎牙、斗鱼当直播，爱奇艺、优酷当点播，抖音、快手当短视频。B 站这种点播、直播混在一起的 App 不用于弱标签。弱标签只能用来起步，评估结论要以真机标签为准。

## 已知的不足

- N3 上同一个用户同时用 IPv4 和 IPv6 时，现在会被当成两个用户。真机抓包加 `--ue` 没有这个问题。
- PCAPdroid 抓的是手机这一侧，时间上和运营商的 N3 差几十毫秒。分类按秒看节奏，影响不大。
- 小窗播放、边看边下载这类混合场景，第一轮先不录，等主干跑通再加。

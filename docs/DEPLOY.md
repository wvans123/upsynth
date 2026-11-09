# 部署到公司的 Linux 服务器

适用于这种服务器：能上网下载软件，但数据不能往外传。代码和依赖可以从外面装进来，抓包、流表、密钥都留在服务器上。

## 要什么

- Linux x86_64 或 arm64，Python 3.10 以上。
- tshark，用来检查合成的 pcap。
- 能访问 GitHub（仓库是私有的，要有访问权限）和 PyPI，或者 PyPI 的国内镜像。

## 安装

先装系统包：

```
# Ubuntu / Debian
sudo apt install -y python3 python3-venv git tshark libgomp1
# CentOS / RHEL / openEuler / 麒麟
sudo dnf install -y python3 git wireshark-cli libgomp
```

再装 uv（Python 的包管理工具）：

```
curl -LsSf https://astral.sh/uv/install.sh | sh     # 或者 pip install uv
```

拉代码。仓库是私有的，用 GitHub 账号登录，或者在 GitHub 上建一个只读的访问令牌：

```
git clone https://github.com/wvans123/upsynth.git    # 提示输入密码时填访问令牌
cd upsynth
uv tool install '.[ml]'                              # 装上 upsynth 命令，带 LightGBM
```

PyPI 慢的话，加国内镜像：`uv tool install '.[ml]' --default-index https://pypi.tuna.tsinghua.edu.cn/simple`。

以后更新：

```
cd upsynth && git pull && uv tool install --force '.[ml]'
```

## 装完自检

```
upsynth --help
python3 -c "from upsynth.sample import make_sample; make_sample('/tmp/s.pcap')"
upsynth ingest /tmp/s.pcap -o /tmp/f.parquet --json
upsynth label  /tmp/f.parquet -o /tmp/l.parquet --json
upsynth profile /tmp/l.parquet -o /tmp/p.json --json
upsynth synth  /tmp/p.json -o /tmp/o.pcap --ues 5 --duration 120 --json   # 看 check.malformed 是不是 0
```

想跑全部测试：`uv venv && uv pip install -e '.[dev,ml]' && .venv/bin/pytest -q`。

## 密钥和数据

- 第一次运行 ingest 时，会在 `~/.upsynth/key` 生成密钥，IP 和 TEID 都用它换成编号。这把密钥只留在这台服务器上。
- 几个人共用数据时，用同一把密钥（环境变量 `UPSYNTH_KEY`，或者 `--key`）。不然同一个用户在不同文件里的编号对不上。
- 原始抓包、`flows.parquet`、`labeled.parquet` 都不出服务器。能拿出来的只有 `profile.json`、模型文件和统计数字，拿出来之前也要按公司规定过一遍。

## 在服务器上用 agent

Claude Code、Codex 这类 agent 会把它读到的内容发给外面的模型服务。所以在这台服务器上要守住一条线：agent 只看汇总，不看明细。

- 让 agent 只跑带 `--json` 的命令。这些命令的返回都是计数、分数、分布，不含单条流和地址。
- 不让 agent 打开 pcap、parquet，也不让它用 `head`、`cat` 看 CSV 明细。
- 公司有内部部署的大模型时，优先用内部的。

agent 的技能文件这样装（在仓库目录里）：

| agent | 做法 |
|---|---|
| Claude Code | `mkdir -p ~/.claude/skills && cp -r skills/upsynth ~/.claude/skills/` |
| Codex | `mkdir -p ~/.codex/skills && cp -r skills/upsynth ~/.codex/skills/` |
| DSH | `mkdir -p ~/.agents/skills && cp -r skills/upsynth ~/.agents/skills/` |

## 常见问题

- `import lightgbm` 报找不到 `libgomp`：装上面列的 `libgomp1` 或 `libgomp`。
- synth 返回里 `check.ok` 是 null：没找到 tshark。装上，或者设 `UPSYNTH_TSHARK=/path/to/tshark`。
- 抓包太大（几十 GB）：ingest 是流式读的，内存不会跟着涨，但会比较慢。先用 `editcap -A/-B` 按时间切一段试。

# upsynth

5G 用户面流量识别与合成。

输入 N3（GTP-U）或 N6（裸 IP）抓包，识别每条流属于哪个应用，抽出去标识的业务剖面，再按剖面合成逼真的用户面 pcap。合成结果用 tshark 检查，malformed 必须为零。做成命令行加 skill，Claude Code、Codex、Cursor、DSH 都能用。

```
pcap -> ingest -> flows.parquet -> label -> labeled.parquet -> profile -> profile.json -> synth -> out.pcap + labels.csv
```

## 安装

需要 Python 3.10 以上。

```
uv tool install .        # 或 pipx install .
upsynth --help
```

可选：`pip install 'upsynth[ndpi]'` 加 nDPI 弱标签；`pip install 'upsynth[mcp]'` 加 MCP 服务（`upsynth-mcp`）。合成后的检查要用 tshark（装 Wireshark 即可，Windows 也行）。

## 用法

```
upsynth ingest  capture.pcap    -o flows.parquet
upsynth label   flows.parquet   -o labeled.parquet --pfd pfd.json
upsynth profile labeled.parquet -o profile.json
upsynth synth   profile.json    -o out.pcap --ues 20 --duration 600 --iface n3
```

每个命令加 `--json` 输出一个 JSON 对象，`--help` 有全部参数。`upsynth kb` 检查知识库、查域名、导出 PFD。

没有现成抓包时，先用自带的样例走一遍：

```
python -c "from upsynth.sample import make_sample; make_sample('sample.pcap')"
```

`examples/` 里有一份 Open5GS + UERANSIM 跑出来的真实 N3 抓包和它的剖面，做法见 `examples/README.md`。

## 数据规矩

- 真实抓包只在本机用，不进仓库。
- ingest 第一步就把 IP 和 TEID 换成 HMAC token，不保留 payload。密钥在 `~/.upsynth/key`。
- profile.json 只有分布（直方图、占比、聚类中心），可以出公司。流少的应用会并进 `other`。
- 合成流量的服务器地址在 198.18.0.0/15 和 2001:db8::/32，不指向真实主机。

## 装进各家 agent

skill 在 `skills/upsynth/SKILL.md`，前提是 `upsynth` 命令在 PATH 上。

| 客户端 | 做法 |
|---|---|
| Claude Code | `/plugin marketplace add <仓库地址或本地路径>`，再 `/plugin install upsynth@upsynth` |
| Codex | 复制 `skills/upsynth` 到 `~/.codex/skills/` |
| Cursor | 复制到 `~/.cursor/skills/`（或项目的 `.cursor/skills/`） |
| DSH | 复制到 `~/.agents/skills/` 或 `~/.dsh/skills/`，不需要插件清单，`dsh plugin add` 不用于 skill |
| 通用 | `npx skills add <仓库地址>` |

不走 shell 的客户端用 MCP：`upsynth-mcp`（stdio）。

## 文档

- `docs/DESIGN.md`：每一步怎么做、数据格式、和简报不同的取舍。
- `skills/upsynth/SKILL.md`：给 agent 的用法、脱敏规则、常见坑。
- `BRIEF.md`：最初的开工简报。

## 测试

```
pip install -e '.[dev]'
pytest
```

装了 tshark 时会多跑对账和零 malformed 检查。

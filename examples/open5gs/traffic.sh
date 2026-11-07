#!/usr/bin/env bash
# What the UE does: open web pages with their page resources, an HTTP/3 request, NTP, a plain HTTP check.
# Runs inside the UE network namespace, so every packet crosses N3.
set -u
W=$(mktemp -d)
SITES=(
  https://www.baidu.com https://www.bilibili.com https://www.zhihu.com https://www.taobao.com https://www.jd.com
  https://www.qq.com https://www.163.com https://www.douyin.com https://www.xiaohongshu.com https://www.mi.com
  https://www.huawei.com https://www.apple.com.cn https://www.microsoft.com https://cn.bing.com https://github.com
  https://www.amap.com https://www.ctrip.com https://www.meituan.com https://www.iqiyi.com https://v.qq.com
  https://music.163.com https://www.toutiao.com https://www.dingtalk.com https://www.feishu.cn
  https://www.deepseek.com https://weibo.com https://www.kuaishou.com https://www.alipay.com
)
H3_SITES=(https://www.taobao.com https://g.alicdn.com https://www.baidu.com https://www.qq.com https://www.bilibili.com)

python3 "$(dirname "$0")/ntp_query.py" ntp.aliyun.com || true
curl -s -o /dev/null -m 8 http://connect.rom.miui.com/generate_204 || true

for round in 1 2; do
  for s in $(printf '%s\n' "${SITES[@]}" | shuf); do
    wget -q -p -H -e robots=off --timeout=8 --tries=1 -l 1 --max-redirect=3 \
      -U "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36" \
      -P "$W" "$s" >/dev/null 2>&1 &
    sleep "$(shuf -i 1-4 -n 1)"
  done
  if [ -x /opt/h3venv/bin/python ]; then
    for s in "${H3_SITES[@]}"; do /opt/h3venv/bin/python "$(dirname "$0")/h3_get.py" "$s" || true; done
  fi
  python3 "$(dirname "$0")/ntp_query.py" ntp.tencent.com || true
done
wait
rm -rf "$W"

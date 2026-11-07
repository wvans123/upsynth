#!/usr/bin/env bash
# Bring up UERANSIM gNB + UE against the local Open5GS, move the UE tunnel into its own network
# namespace (default route and DNS through 5G), record N3 (GTP-U on lo) and N6 (ogstun) while
# traffic.sh browses. Run as root after setup.sh. Output: $OUT/n3.pcap, $OUT/n6.pcap
set -euo pipefail
OUT=${OUT:-/tmp/upsynth-capture}
DURATION=${DURATION:-240}
HERE=$(cd "$(dirname "$0")" && pwd)
U=/opt/UERANSIM
mkdir -p "$OUT"
cleanup() {
  kill "${TCPDUMP_N3:-}" "${TCPDUMP_N6:-}" "${UE:-}" "${GNB:-}" 2>/dev/null || true
  ip netns del ue 2>/dev/null || true
}
trap cleanup EXIT

systemctl restart open5gs-amfd open5gs-smfd open5gs-upfd
sleep 3

tcpdump -i lo -U -w "$OUT/n3.pcap" udp port 2152 >/dev/null 2>&1 & TCPDUMP_N3=$!
tcpdump -i ogstun -U -w "$OUT/n6.pcap" >/dev/null 2>&1 & TCPDUMP_N6=$!

"$U/build/nr-gnb" -c "$U/config/open5gs-gnb.yaml" > "$OUT/gnb.log" 2>&1 & GNB=$!
sleep 2
"$U/build/nr-ue" -c "$U/config/open5gs-ue.yaml" > "$OUT/ue.log" 2>&1 & UE=$!
for _ in $(seq 30); do ip -4 addr show uesimtun0 2>/dev/null | grep -q inet && break; sleep 1; done
UE_IP=$(ip -4 -o addr show uesimtun0 | awk '{print $4}' | cut -d/ -f1)
echo "UE IP $UE_IP"

ip netns add ue
ip link set uesimtun0 netns ue
ip netns exec ue ip link set lo up
ip netns exec ue ip addr add "$UE_IP/32" dev uesimtun0
ip netns exec ue ip link set uesimtun0 up
ip netns exec ue ip route add default dev uesimtun0
mkdir -p /etc/netns/ue
echo "nameserver 223.5.5.5" > /etc/netns/ue/resolv.conf

ip netns exec ue env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  timeout "$DURATION" bash "$HERE/traffic.sh" || true
sleep 3
echo "captures in $OUT"

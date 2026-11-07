#!/usr/bin/env bash
# Open5GS (5GC) + UERANSIM (gNB + UE) on one Ubuntu 24.04 machine or VM, everything on loopback.
# Run as root. Afterwards: run.sh brings up gNB + UE and records N3 (GTP-U on lo) while the UE browses.
set -euo pipefail

# --- packages --------------------------------------------------------------
if [ -n "${UBUNTU_MIRROR:-}" ]; then
  sed -i "s#http://ports.ubuntu.com/ubuntu-ports#${UBUNTU_MIRROR}#g; s#http://archive.ubuntu.com/ubuntu#${UBUNTU_MIRROR}#g" \
    /etc/apt/sources.list.d/ubuntu.sources
fi
apt-get update
apt-get install -y software-properties-common gnupg curl git make gcc g++ cmake libsctp-dev lksctp-tools \
  iproute2 iptables tcpdump python3-venv

# MongoDB holds the subscriber database (UDR)
if ! command -v mongod >/dev/null; then
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" \
    > /etc/apt/sources.list.d/mongodb-org-8.0.list
  apt-get update
  apt-get install -y mongodb-org
fi
systemctl enable --now mongod

add-apt-repository -y ppa:open5gs/latest
apt-get update
apt-get install -y open5gs

# --- subscriber (same IMSI/K/OPc as UERANSIM's open5gs-ue.yaml) -------------
# open5gs-dbctl ships in the source tree, not in the package
if ! command -v open5gs-dbctl >/dev/null; then
  curl -fsSL -o /usr/local/bin/open5gs-dbctl https://raw.githubusercontent.com/open5gs/open5gs/main/misc/db/open5gs-dbctl
  chmod +x /usr/local/bin/open5gs-dbctl
fi
if ! open5gs-dbctl showall | grep -q 999700000000001; then
  open5gs-dbctl add 999700000000001 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
fi
open5gs-dbctl showall | grep -q 999700000000001

# --- UE traffic leaves through the UPF ---------------------------------------
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE

# --- UERANSIM -----------------------------------------------------------------
if [ ! -x /opt/UERANSIM/build/nr-gnb ]; then
  git clone --depth 1 https://github.com/aligungr/UERANSIM /opt/UERANSIM
  make -C /opt/UERANSIM -j"$(nproc)"
fi
# HTTP/3 client for traffic.sh
[ -x /opt/h3venv/bin/python ] || { python3 -m venv /opt/h3venv && /opt/h3venv/bin/pip install -q aioquic; }
echo "setup done"

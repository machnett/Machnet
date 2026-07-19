#!/bin/bash
# Local single-machine test of Machnet's TCP transport, bridging the DPDK
# kernel-bypass stack to the ordinary Linux kernel stack via a DPDK net_tap
# virtual device.
#
# Topology:
#   tcp_msg_gen (POSIX sockets, kernel stack)          Machnet engine (DPDK) + msg_gen --protocol tcp
#           10.0.0.2/24 on mtap0  <==== net_tap L2 link ====>  port MAC 02:00:00:00:00:01, IP 10.0.0.1
#
# Requires: a Release build in ./build, hugepages reserved, and sudo.
# Usage: ./scripts/local_tap_tcp_test.sh        (run from repo root)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${REPO}/build"
MACHNET_MAC="02:00:00:00:00:01"
MACHNET_IP="10.0.0.1"
TAP_IF="mtap0"
KERNEL_MAC="02:00:00:00:00:02"
KERNEL_IP="10.0.0.2/24"
PORT=888
MSG_SIZE=64
WINDOW=8
RUN_SECS="${1:-8}"

cleanup() {
  echo "--- cleanup ---"
  sudo pkill -f 'apps/machnet/machnet'   2>/dev/null || true
  sudo pkill -f 'apps/msg_gen/msg_gen'   2>/dev/null || true
}
trap cleanup EXIT

# 1. Engine config with a net_tap vdev (needs the vdev-support patch to the engine).
sudo mkdir -p /var/run/machnet && sudo chmod 755 /var/run/machnet
sudo tee /var/run/machnet/local_config.json >/dev/null <<EOF
{
  "machnet_config": {
    "${MACHNET_MAC}": {
      "ip": "${MACHNET_IP%/*}",
      "vdev": "net_tap0,iface=${TAP_IF},mac=${MACHNET_MAC}"
    }
  }
}
EOF

# 2. Fresh DPDK/hugepage state, then start the engine.
sudo rm -f /dev/hugepages/rtemap_* /var/run/dpdk/rte/* 2>/dev/null || true
echo "--- starting Machnet engine ---"
sudo "${BUILD}/src/apps/machnet/machnet" --config_json /var/run/machnet/local_config.json \
  >/tmp/machnet_engine.log 2>&1 &
until ip link show "${TAP_IF}" >/dev/null 2>&1; do sleep 1; done

# 3. Configure the kernel end of the tap (distinct MAC + IP).
sudo ip link set "${TAP_IF}" down
sudo ip link set "${TAP_IF}" address "${KERNEL_MAC}"
sudo ip link set "${TAP_IF}" up
sudo ip addr add "${KERNEL_IP}" dev "${TAP_IF}" 2>/dev/null || true
echo "--- kernel tap ready: $(ip -brief addr show ${TAP_IF}) ---"

# 4. Start the Machnet TCP server (attaches to the engine over shared memory).
echo "--- starting Machnet TCP server on ${MACHNET_IP}:${PORT} ---"
sudo "${BUILD}/src/apps/msg_gen/msg_gen" --local_ip "${MACHNET_IP}" --local_port "${PORT}" \
  --protocol tcp --msg_size "${MSG_SIZE}" >/tmp/machnet_server.log 2>&1 &
until grep -q LISTENING /tmp/machnet_server.log 2>/dev/null; do sleep 1; done
echo "--- server listening ---"

# 5. Drive it with a standard POSIX TCP client (kernel stack).
echo "--- POSIX client -> Machnet, ${RUN_SECS}s ---"
stdbuf -oL timeout "${RUN_SECS}" "${BUILD}/src/apps/tcp_msg_gen/tcp_msg_gen" \
  --local_ip=0.0.0.0 --remote_ip="${MACHNET_IP}" --remote_port="${PORT}" \
  --msg_size="${MSG_SIZE}" --msg_window="${WINDOW}" || true

echo "--- engine's view of the flow ---"
grep -E "TCP \[10" /tmp/machnet_engine.log | tail -1 || true

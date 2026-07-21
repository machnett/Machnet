#!/bin/bash
# Local single-machine test of Machnet's TCP transport over a *vhost* port:
# the engine runs on a DPDK virtio_user virtual device backed by the kernel
# vhost-net module, instead of a physical NIC. This is the vhost sibling of
# scripts/local_tap_tcp_test.sh (see docs/LOCAL_SINGLE_HOST_TESTING.md for
# the full local-testing guide); vhost-net moves packets in the kernel's
# vhost worker thread, so it is the higher-throughput local datapath.
#
# Topology (single engine -- Machnet<->Machnet on one host is unsupported,
# see docs/LOCAL_SINGLE_HOST_TESTING.md section 7):
#
#   tcp_msg_gen (POSIX sockets, kernel stack)      Machnet engine (DPDK) + msg_gen --protocol tcp
#     10.0.0.2/24 on mvhost0  <== vhost-net ==>  virtio_user port, MAC 02:00:00:00:00:01, IP 10.0.0.1
#
# The virtio_user device lacks checksum offloads, so the engine computes
# checksums in software for this port (see Packet::compute_software_checksums).
#
# Requires: a Release build in ./build, hugepages reserved, /dev/vhost-net
# (modprobe vhost_net), and sudo.
# Usage: ./examples/local_vhost_test.sh [run_seconds]   (run from repo root)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${REPO}/build"
MACHNET_MAC="02:00:00:00:00:01"
MACHNET_IP="10.0.0.1"
VHOST_IF="mvhost0"
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

# 0. The vhost-net kernel module provides /dev/vhost-net, the backend that
#    services the virtio_user port and materializes the kernel-side interface.
sudo modprobe vhost_net
[ -c /dev/vhost-net ] || { echo "ERROR: /dev/vhost-net missing"; exit 1; }

# 1. Engine config with a virtio_user vdev backed by vhost-net.
sudo mkdir -p /var/run/machnet && sudo chmod 755 /var/run/machnet
sudo tee /var/run/machnet/local_config.json >/dev/null <<EOF
{
  "machnet_config": {
    "${MACHNET_MAC}": {
      "ip": "${MACHNET_IP%/*}",
      "vdev": "virtio_user0,path=/dev/vhost-net,queues=1,queue_size=1024,iface=${VHOST_IF},mac=${MACHNET_MAC}"
    }
  }
}
EOF

# 2. Fresh DPDK/hugepage state, then start the engine.
sudo rm -f /dev/hugepages/rtemap_* /var/run/dpdk/rte/* 2>/dev/null || true
echo "--- starting Machnet engine ---"
sudo "${BUILD}/src/apps/machnet/machnet" --config_json /var/run/machnet/local_config.json \
  >/tmp/machnet_engine.log 2>&1 &
until ip link show "${VHOST_IF}" >/dev/null 2>&1; do sleep 1; done

# 3. Configure the kernel end (distinct MAC + IP). Disable TX offloads so the
#    kernel fully checksums outgoing packets instead of leaving them partial
#    for the "device" (Machnet does not verify or fix up RX checksums).
sudo ip link set "${VHOST_IF}" down
sudo ip link set "${VHOST_IF}" address "${KERNEL_MAC}"
sudo ethtool -K "${VHOST_IF}" tx off rx off 2>/dev/null || true
sudo ip link set "${VHOST_IF}" up
sudo ip addr add "${KERNEL_IP}" dev "${VHOST_IF}" 2>/dev/null || true
echo "--- kernel vhost if ready: $(ip -brief addr show ${VHOST_IF}) ---"

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

# Local single-host testing of Machnet (net_tap bridge)

This document is a hand-off for running and testing Machnet — including the TCP
transport from the `tcp-handshake-csum` work — **entirely on one machine**, with
no second host and no special NIC. It also records what was validated, the
architectural limits discovered, and how to reproduce everything.

---

## 1. TL;DR — what works locally

| Scenario | How | Status |
|---|---|---|
| Standard Linux TCP client ↔ Machnet DPDK TCP server | `net_tap` bridge (kernel stack ↔ DPDK) | ✅ works, ~180K msg/s |
| Two Machnet apps attached to one engine, serving concurrent external clients | two channels/listeners on one engine | ✅ works |
| UDP datapath | unit tests + datapath review | ✅ functional, no perf regression |
| **Two Machnet stacks talking to each other on one host** | needs 2 engines | ❌ not supported (see §7) |

One-command reproduction of the TCP interop test:

```bash
./scripts/local_tap_tcp_test.sh          # from repo root; needs sudo + hugepages
```

---

## 2. The core idea: bridging DPDK ↔ the kernel with `net_tap`

Machnet is a **kernel-bypass** stack: it binds a NIC via DPDK, so ordinary Linux
sockets can't see it. To test against a normal Linux TCP client on the *same*
machine, we give Machnet a **DPDK `net_tap` virtual device** instead of a real
NIC. `net_tap` creates a kernel TAP interface that is the *other end* of
Machnet's DPDK port — a point-to-point L2 link between the Linux kernel stack and
Machnet's DPDK stack.

```
 tcp_msg_gen (POSIX sockets, kernel stack)          Machnet engine (DPDK) + msg_gen --protocol tcp
   10.0.0.2/24 on mtap0, MAC …:02  <==== net_tap L2 link ====>  port MAC …:01, IP 10.0.0.1, TCP :888
```

Why `net_tap` and not `vhost-user`/`virtio-user`/`af_xdp`:
- `vhost-user` needs a virtio *front-end* (a VM or another DPDK/virtio process) —
  a plain host socket can't drive it.
- `virtio-user`+kernel `vhost-net` is higher-throughput but more moving parts.
  A ready-made variant of this test over vhost now exists as
  `examples/local_vhost_test.sh` (same topology, `virtio_user0` +
  `/dev/vhost-net` instead of `net_tap0`). Because `virtio_user` — unlike
  `net_tap` — has no checksum offloads, the engine falls back to software
  checksums on such ports (`Packet::compute_software_checksums`).
- `af_xdp`/`af_packet` PMD on a `veth` pair also works but is fiddlier.
- `net_tap` is the simplest reliable choice for a *functional* single-host test.

This works because the engine already **answers ARP** for its own IP and, on the
server path, learns the client's MAC from the incoming SYN frame — so a kernel
TCP client can resolve Machnet and complete a handshake.

---

## 3. Prerequisites (Ubuntu 24.04)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build pkg-config \
  libdpdk-dev nlohmann-json3-dev libhugetlbfs-dev uuid-dev
```

Ubuntu 24.04 ships DPDK 23.11, which satisfies Machnet's `libdpdk>=23.11 <24.0`.

Reserve hugepages (needed by DPDK EAL):

```bash
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

Initialize submodules and build (Release):

```bash
git submodule update --init --recursive
rm -rf build && mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja -j$(nproc)
```

---

## 4. The `vdev` config option (added for local testing)

The engine historically only supported **PCIe** NICs (it resolves a PCIe address
by MAC and passes a `-a <addr>` allowlist to EAL). To use a DPDK virtual device,
the interface config now accepts an optional **`vdev`** key:

```json
{
  "machnet_config": {
    "02:00:00:00:00:01": {
      "ip": "10.0.0.1",
      "vdev": "net_tap0,iface=mtap0,mac=02:00:00:00:00:01"
    }
  }
}
```

When `vdev` is present the engine:
- skips PCIe-address discovery for that interface,
- appends `--vdev <spec>` to the EAL options,
- appends `--no-pci` (so EAL doesn't probe host NICs).

The interface is still matched to its DPDK port **by MAC**, so the `mac=` in the
vdev spec must equal the config key MAC.

Code: `src/core/machnet_config.cc`, `src/include/machnet_config.h`.
Tests: `src/core/machnet_config_test.cc` (runs without DPDK/hugepages/sudo).

---

## 5. Running the TCP interop test (Linux client ↔ Machnet server)

Use the script (`scripts/local_tap_tcp_test.sh`) or these manual steps:

```bash
# 1. Engine config with a net_tap vdev
sudo mkdir -p /var/run/machnet && sudo chmod 755 /var/run/machnet
sudo tee /var/run/machnet/local_config.json >/dev/null <<'EOF'
{"machnet_config":{"02:00:00:00:00:01":{"ip":"10.0.0.1",
  "vdev":"net_tap0,iface=mtap0,mac=02:00:00:00:00:01"}}}
EOF

# 2. Clear stale DPDK state and start the engine (spins a core in poll mode)
sudo rm -f /dev/hugepages/rtemap_* /var/run/dpdk/rte/*
sudo ./build/src/apps/machnet/machnet --config_json /var/run/machnet/local_config.json &

# 3. Configure the kernel end of the tap (distinct MAC + IP)
sudo ip link set mtap0 down
sudo ip link set mtap0 address 02:00:00:00:00:02
sudo ip link set mtap0 up
sudo ip addr add 10.0.0.2/24 dev mtap0

# 4. Machnet TCP server (attaches to the engine over shared memory)
sudo ./build/src/apps/msg_gen/msg_gen --local_ip 10.0.0.1 --local_port 888 \
     --protocol tcp --msg_size 64 &

# 5. Standard POSIX TCP client (kernel stack) drives it
./build/src/apps/tcp_msg_gen/tcp_msg_gen --local_ip=0.0.0.0 \
     --remote_ip=10.0.0.1 --remote_port=888 --msg_size=64 --msg_window=8
```

Expected: the client prints `[CLIENT] Connected.` and sustained throughput; both
stacks agree on the 4-tuple:
- Machnet: `TCP [10.0.0.2:<port> <-> 10.0.0.1:888] [ESTABLISHED]`
- Kernel: `ss -tn` shows `ESTAB 10.0.0.2:<port> 10.0.0.1:888`

Sanity check the L2 path without traffic: `ping 10.0.0.1` won't get ICMP replies
from Machnet, but `ip neigh show 10.0.0.1` should resolve to `02:00:00:00:00:01`
(proves ARP crossed the bridge).

---

## 6. Two Machnet applications attached to one engine

Multiple apps can attach to the same engine concurrently — each `machnet_attach()`
opens its own shared-memory channel. Validated by running two Machnet TCP servers
on different ports and driving both with two external Linux clients at once:

```bash
sudo ./build/src/apps/msg_gen/msg_gen --local_ip 10.0.0.1 --local_port 888 --protocol tcp --msg_size 64 &
sudo ./build/src/apps/msg_gen/msg_gen --local_ip 10.0.0.1 --local_port 889 --protocol tcp --msg_size 64 &
# then two tcp_msg_gen clients against :888 and :889 in parallel
```

The engine status output then shows two **Active channels** and two **Listeners
(TCP)**, and both servers report throughput simultaneously.

---

## 7. Architectural limit: single-host Machnet ↔ Machnet is NOT supported

Two *Machnet* stacks talking to each other on one host does **not** work with the
current codebase, for three independent reasons:

1. **No same-host loopback.** An engine always transmits flows to the wire; a
   client app connecting to a server app on the same engine/IP hangs (confirmed).
2. **One controller socket per host.** Apps connect to a hardcoded AF_UNIX path
   (`MACHNET_CONTROLLER_DEFAULT_PATH` in `src/ext/machnet_common.h`), so two
   engines can't coexist.
3. **No DPDK `--file-prefix`.** Two DPDK primary processes would collide on the
   hugepage/runtime files, and each engine only TXes on its own port (channel→
   engine assignment is by hash, not by IP).

Machnet is designed as **one engine per host, inter-host**. To test real
Machnet↔Machnet (TCP or UDP), use **two machines**, each running its own engine —
see `docs/TCP_EXPERIMENT_README.md` (Experiment 2) and the main `README.md`.

Enabling single-host multi-engine would require: a configurable controller socket
path (engine + `libmachnet`), a per-engine DPDK `--file-prefix`, and IP-aware
channel→port binding. This was intentionally **not** done here (out of scope).

---

## 8. UDP: functional + no performance regression

UDP is Machnet's primary/most-common path and must not regress. Findings:

- **Functional:** `flow_test` (5 UDP TX/RX-queue + reassembly cases) and
  `machnet_engine_test` (2 cases, engine UDP datapath) pass against the branch's
  `engine.h`.
- **No perf regression** on the UDP hot path (`process_rx_ipv4`):
  - The protocol `switch (ipv4h->next_proto_id)` **already existed** on `main`
    with `[[likely]] case kUdp`; the TCP work only *added* a `case kTcp` after it.
    UDP is still the first, branch-predicted case.
  - `udph`/`pkt_key` parsing moved *into* the UDP case — identical work for UDP
    packets, and now skipped for non-UDP.
  - The length check changed from `!=` to `<` (to tolerate Ethernet min-frame
    padding) — the same single comparison.
  - Net: **no added branches on the UDP fast path**; effectively identical
    instruction cost.

Note: a *runtime* UDP latency benchmark needs two Machnet endpoints (§7), i.e.
two hosts. On real hardware, use `msg_gen --protocol udp` client/server across two
machines and read the P50/P99/P99.9 RTT that `msg_gen` prints.

---

## 9. Tests

Run the full suite (needs hugepages + sudo for the DPDK-backed tests):

```bash
cd build
sudo rm -f /dev/hugepages/rtemap_* /var/run/dpdk/rte/*
sudo ctest --output-on-failure
```

Relevant tests:
- `tcp_flow_test` — 58 cases for the TCP flow (handshake, RTO/retransmit, checksum, window, TIME_WAIT).
- `flow_test`, `machnet_engine_test` — UDP datapath.
- `machnet_config_test` — the `vdev` config option (no DPDK needed).

---

## 10. Gotchas

- **Stale hugepage segments.** If EAL fails with `get_seg_fd … Permission denied`
  or `Cannot init memory`, clear leftovers: `sudo rm -f /dev/hugepages/rtemap_*
  /var/run/dpdk/rte/*` before starting.
- **`net_tap` MAC.** `net_tap` gives the kernel tap the same MAC as the DPDK port
  by default; set a distinct kernel-side MAC (`ip link set mtap0 address …`) so
  ARP resolves cleanly.
- **`-c 0x0` in older tests.** `dpdk_test`, `flow_test`, `machnet_engine_test`
  historically hardcoded an invalid empty coremask that DPDK 23.11 rejects; this
  is fixed to `-c 0x1` on `main`.
- **The engine spins a core** at 100% in DPDK poll mode — stop it when idle.

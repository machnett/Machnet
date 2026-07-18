# EPS channel backend (Option B)

This document describes Machnet's EPS channel backend: the integration that
lets the Machnet engine talk directly to the EPS eBPF datapath ("Accelerated
Networking" — syscall-intercepting BPF hooks + per-connection rings), removing
the userspace poller from the data path.

## Overview

A regular Machnet channel moves messages between an application and the stack
through two shm rings (Machnet→App and App→Machnet). An **EPS channel**
(`juggler::shm::EpsChannel`, `src/include/eps_channel.h`) replaces both:

- **TX intake** — the engine drains the EPS kernel `tx_ring`
  (`BPF_MAP_TYPE_RINGBUF`, filled by the eBPF `sendto()` hook) directly via
  mmap, converting each record into a `MsgBuf` chain for the bound flow.
- **RX delivery** — completed messages are written into the destination
  connection's `rx_ring` (`BPF_MAP_TYPE_USER_RINGBUF` inner map of the
  `rx_rings` hash-of-maps) as `[u32 len][payload]` samples, followed by
  exactly one eventfd token per message (the EPS semaphore protocol).

The channel's shm segment still exists: it provides the engine's buffer pool
(so DMA/zero-copy registration is unchanged) and the ctrl SQ/CQ rings, which
carry both the standard control ops and the new EPS ops below. The engine
itself required **no changes**: `EnqueueMessages` / `DequeueMessages` /
`DequeueCtrlRequests` became virtual on `ShmChannel` and `EpsChannel`
overrides them.

## How an EPS channel is created

The EPS daemon (not the poller) owns the control plane. It attaches with:

```c
void *ctx = machnet_attach_ex(MACHNET_CHANNEL_INFO_FLAG_EPS);
```

The controller then creates an `EpsChannel` instead of a regular `Channel`,
and calls `InitEps()`, which opens the pinned maps `tx_ring` and `rx_rings`
from the BPF pin directory (default `/sys/fs/bpf/accelerated`, overridable
with the `MACHNET_EPS_BPF_DIR` environment variable) and mmaps the tx_ring
(consumer page RW, producer page RO, double-mapped data area RO). If the pins
are missing, channel creation fails and the daemon gets an error.

The daemon keeps using the same channel for `machnet_connect()` /
`machnet_listen()` (UDP or TCP variants) exactly as in the poller-based
integration (Option A).

`InitEps()` also opens the `tx_blocked` pin when present: since the engine
now drains the tx_ring, it also inherits the poller's job of waking senders
parked in a blocking `sendto()` (wake on drain-to-empty, every 64 records
under sustained backpressure, and a ~1 s sweep fallback). Without the pin,
blocking-sender wake is disabled, as in the poller.

## The daemon ↔ engine EPS protocol

Three new ctrl opcodes (see `src/ext/machnet_common.h`), all carried in
`MachnetCtrlQueueEntry_t.eps_bind` (`MachnetEpsConnBind_t = {flow, pid, fd}`):

| Opcode | Direction | Meaning |
|---|---|---|
| `MACHNET_CTRL_OP_EPS_BIND_CONN` | daemon → stack (ctrl SQ) | Bind EPS connection `{pid, fd}` to `flow`. TX records from this conn_key are sent on `flow`; RX messages for the reversed tuple are delivered to this connection's rx_ring. Completion (`MACHNET_CTRL_OP_STATUS`, matching `id`) is posted on the CQ. |
| `MACHNET_CTRL_OP_EPS_UNBIND_CONN` | daemon → stack (ctrl SQ) | Remove the binding (only `pid`/`fd` are used) and drop the cached rx_ring/eventfd handles. |
| `MACHNET_CTRL_OP_EPS_NEW_FLOW` | stack → daemon (ctrl CQ, `id == 0`) | A message arrived on a flow with no bound connection (e.g., an inbound connection from a remote host). The daemon should perform its accept-side brokering (create the rx_ring entry, wake the parked accept) and answer with a BIND_CONN. The event is re-posted about once per second while messages for the flow remain parked, so the daemon must treat NEW_FLOW (and BIND_CONN handling) as idempotent. |

**Flow orientation contract:** `eps_bind.flow` is always in *TX orientation* —
`src_ip/src_port` is the **local** Machnet endpoint, exactly as returned by
`machnet_connect()`. NEW_FLOW events are posted already swapped into this
orientation, so the daemon echoes the tuple back verbatim.

Typical flows:

- **Outbound (local app connects to remote):** daemon sees the EPS SETUP
  event → `machnet_connect()` on this channel → gets `flow` → sends
  `BIND_CONN{flow, pid, fd}`.
- **Inbound (remote connects to local listener):** daemon has already called
  `machnet_listen()`. First message on the new flow triggers a `NEW_FLOW`
  CQ event; the daemon runs its accept brokering, then sends
  `BIND_CONN{flow-as-given, accepted_pid, accepted_fd}`.

Messages that arrive before the BIND are parked (bounded: 256 messages, aged
out after ~8 s) and flushed in order when the BIND arrives. TX records whose
conn_key is unbound are **held in the tx_ring** (consumer position not
advanced), mirroring the EPS poller's hold-slot backpressure — so the daemon
should send BIND_CONN promptly after connect completes.

## Semantics and limitations

- **Ctrl latency:** the engine polls the ctrl SQ on its slow tick (~1 s), so
  BIND/NEW_FLOW handling has up to ~1 s latency. Data-path operations
  (tx_ring drain, rx_ring delivery) run every engine loop iteration.
- **Message size:** EPS records are capped at 1500 bytes (`kEpsMaxPayload`)
  in both directions; larger reassembled messages are dropped with a stat.
- **Drops:** a full rx_ring drops the message after a bounded wait (matching
  existing `TcpFlow` behavior when the app ring is full); the eventfd
  token-per-message invariant is preserved (token written only after a
  successful submit).
- **Head-of-line:** one unbound connection's held TX record blocks later
  records in the shared tx_ring (inherited from the poller design).
- **Threading:** one engine thread owns the channel; the libbpf
  `user_ring_buffer` producer API is not thread-safe, so a single EPS
  channel must not be served by multiple engines. Do not run the poller's
  data path concurrently with an EPS channel on the same rings.
- **Ownership:** the engine only *reads* `rx_rings` (lookup + open-by-id);
  creation/deletion of rx_rings entries, `connect_map`, and `bind_map`
  remain exclusively the daemon's, per the EPS ownership rules.
- **Privileges:** Machnet must be able to `bpf_obj_get` the pins and use
  `pidfd_getfd` on EPS apps (root, as required for DPDK anyway).

## Build

The backend needs libbpf ≥ 1.0 (for the `user_ring_buffer` API). CMake
detects it via pkg-config; when found, `MACHNET_EPS_ENABLED` is defined and
`core` links `PkgConfig::LIBBPF`. Without libbpf, Machnet builds as before
and EPS channel requests fail with a clear error.

Note: both the Machnet service and the daemon must be built from the same
tree — `MachnetCtrlQueueEntry_t` and `machnet_channel_info_t` grew, which is
an ABI change for the ctrl rings and the controller socket protocol.

## Testing

- `src/core/drivers/shm/eps_ring_test.cc` unit-tests the BPF ringbuf
  consumer protocol (`EpsTxRingReader`, `src/include/eps_ring.h`) against
  synthetic memory: busy/discard bits, hold-slot, wraparound via the double
  mapping, and consumer-position seeding.
- End-to-end testing requires the EPS custom kernel + loaded BPF programs
  and a DPDK NIC; see the EPS repo's `demo.sh` for the app-side setup.

# EPS ↔ Machnet Option B — Hand-off Document

**Date:** 2026-07-18
**Branch:** `eps-option-b` (commit `33fa678`, based on `tcp-7-02-2026`)
**Audience:** whoever picks this up — Linux bring-up, daemon-side changes, and
end-to-end testing.
**Companion docs:** [EPS_DESIGN.md](EPS_DESIGN.md) (architecture & rationale),
[EPS.md](EPS.md) (the daemon-facing contract). Read this document first, the
contract second, the design doc when you need the "why".

---

## 1. One-paragraph summary

The Machnet engine can now speak the EPS eBPF datapath directly: a new
`EpsChannel` backend drains the EPS kernel `tx_ring` and delivers received
messages into per-connection `USER_RINGBUF` rx_rings with eventfd wakeups,
eliminating the userspace poller from the per-message path ("Option B"). The
engine core is unchanged — three channel methods became virtual and all EPS
logic lives in the new backend. The EPS daemon remains control-plane only,
driving flow setup over the channel's existing ctrl rings with three new
opcodes. **The Machnet side is code-complete and unit-tested where possible,
but has never been compiled on Linux** (dev machine was macOS; DPDK/libbpf are
Linux-only). The daemon-side changes are specified but not implemented.

## 2. State snapshot

| Item | State |
|---|---|
| Machnet-side implementation (`EpsChannel`, seam, ctrl protocol, build) | **Done**, committed `33fa678` on `eps-option-b` |
| Ring-consumer unit tests (`eps_ring_test`) | **Passing** (8/8, incl. ASan-clean) on macOS with vendored gtest; will self-register in `ctest` on Linux |
| Full Linux compile (DPDK + libbpf) | **Not yet attempted** — first task |
| Daemon-side changes (EPS repo) | **Not started** — specified in §6 |
| BPF-side changes (EPS repo) | **Not started** — 2 small hook changes, §6 |
| End-to-end test | Blocked on the above |
| Option A (poller bridge) | Working (user-verified) — remains the fallback; **never run its data path concurrently with an EpsChannel** |

Uncommitted in the working tree (intentionally excluded, pre-existing user
edits): `src/include/tcp_flow.h`, `examples/azure_create_vms.py`.

## 3. Branch topology & the TCP dependency

```
main
 └── tcp-7-02-2026        PR #54 "TCP support" (self-labeled not-ready)
      ├── eps-option-b    ← THIS WORK (commit 33fa678)
      ├── tcp-retransmit-wnd   PR #55: retransmit queue + window-gated TX
      └── tcp-handshake-csum   PR #56 (stacked on #55): SYN-seq fix + TCP csum offload
```

**This matters for testing:** EPS apps are `SOCK_STREAM` and Option B routes
them over Machnet's native TCP, which on `tcp-7-02-2026` still has known
ship-blockers (from the PR #54 review): no data retransmission, TCP checksum
offload not enabled on the port (works only on NICs that recompute L4 csum in
HW, e.g. mlx5 — broken on ixgbe/i40e/virtio), SYN-retransmit breaks the
handshake, RX desync under buffer exhaustion, no TX flow control, DESTROY_FLOW
no-op. PRs #55/#56 fix the first three classes but are themselves not yet
compiled/tested.

**Recommendation:** for anything beyond a lossless-LAN smoke test, rebase or
merge `eps-option-b` onto `tcp-handshake-csum` (#56) so the transport
underneath is at least retransmit-capable. On mlx5 hardware with negligible
loss, `eps-option-b` as-is is fine for first smoke tests. Alternatively, run
the first end-to-end over **UDP Machnet flows** (daemon issues
`MACHNET_CTRL_OP_CREATE_FLOW` instead of the TCP variant) to decouple EPS
integration bugs from TCP transport bugs — the EPS machinery is
transport-agnostic.

## 4. What changed, at a glance

New: `src/include/eps_ring.h` (EPS ABI + ringbuf consumer, dependency-free),
`src/include/eps_channel.h` + `src/core/drivers/shm/eps_channel.cc` (the
backend), `src/core/drivers/shm/eps_ring_test.cc`, `docs/EPS*.md`.
Modified: `src/include/channel.h` (3 virtual methods + virtual dtor +
`AddChannelOfType<C>`), `src/core/machnet_controller.cc` (EPS branch in
`CreateChannel`), `src/ext/machnet_common.h` (+3 opcodes, +`MachnetEpsConnBind_t`
in the ctrl union — **ABI change**), `src/ext/machnet_ctrl.h` (+`flags`),
`src/ext/machnet.c/.h` (+`machnet_attach_ex`), CMake (optional libbpf ≥ 1.1 →
`MACHNET_EPS_ENABLED`).

Full module map and diagrams: [EPS_DESIGN.md §3–4](EPS_DESIGN.md).

## 5. Linux bring-up (exact steps)

```bash
git checkout eps-option-b
git submodule update --init --recursive
sudo apt install libbpf-dev          # need >= 1.1 (user_ring_buffer API)
pkg-config --modversion libbpf       # verify

mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -GNinja ../
#   ► MUST print: "libbpf found - enabling the Machnet EPS channel backend."
#     If it prints "disabled", EPS code silently compiles out — fix libbpf first.
ninja

ctest -R eps_ring_test               # first smoke: 8 tests, no root/NIC needed
sudo ctest                            # full suite (needs hugepages + DPDK)
```

Expected friction on first compile: this code was written blind against
Linux-only headers. Verified by hand against libbpf/glog/channel APIs, but
budget an hour for signature nits. Anything structural, check
`EPS_DESIGN.md §5` before "fixing" — the seam constraints are deliberate.

Smoke-test the channel creation without any daemon changes:

```c
/* minimal probe, linked against machnet_shim, run as root with pins loaded */
machnet_init();
void *ctx = machnet_attach_ex(MACHNET_CHANNEL_INFO_FLAG_EPS);
/* success ⇒ controller log shows "Creating EPS-backed channel" +
   "EpsChannel ... attached to EPS datapath (pin dir: ...)" */
```

Env: `MACHNET_EPS_BPF_DIR` overrides the pin dir (default
`/sys/fs/bpf/accelerated`). Machnet must run as root (it already does for
DPDK; EPS additionally needs `bpf_obj_get` + `pidfd_getfd`).
**Config: keep `engine_threads = 1`** — one engine must own the EPS channel
(libbpf user_ring_buffer producer is not thread-safe, and the controller has a
pre-existing static `engine_index` bug with >1 engine).

## 6. Daemon-side work (the EPS repo) — ordered

Contract reference: [EPS.md](EPS.md). All items were specified in detail in
the session; the design doc §7 has the sequence diagrams.

1. **Ctrl dispatcher** (prerequisite for everything): stop using blocking
   `machnet_connect()`/`machnet_listen()` helpers — the CQ now interleaves
   `EPS_NEW_FLOW` events (id=0) with request completions and the shim helpers
   mis-handle that. Enqueue requests directly
   (`__machnet_channel_ctrl_sq_enqueue`), drain the CQ in the idle loop,
   dispatch by `id`/`opcode`. Both rings are 2 slots; retry full enqueues;
   expect ~1 s per control round-trip (engine slow tick).
2. **Attach**: `machnet_attach_ex(MACHNET_CHANNEL_INFO_FLAG_EPS)` at boot;
   fall back to the Option A poller path on failure.
3. **BPF change #1 — remote connect interception**: the `connect` hook
   currently `PASS`es non-local destinations (the real syscall then fails on
   the eventfd). Stage `pending_connect` + emit SETUP for remote destinations
   too (optionally gated on a daemon-populated allow map).
4. **BPF change #2 — listener discovery**: emit a control event from the
   `listen()` hook (recommended; ~10 lines, new event type, daemon resolves
   the address via `fd_to_addr`) or scan `bind_map` periodically (must filter
   the synthetic `127.0.0.1:50000+` broker entries). Then register
   `machnet_tcp_listen` using the **machnet interface IP** (engine rejects
   non-local IPs; map wildcard binds to the machnet IP). Port conversion:
   `host_port = __builtin_bswap16(bind_key.port)`; IP: `bind_key.ip` is
   already host-order.
5. **Handlers**:
   - SETUP(remote dest) → `CREATE_FLOW`/`TCP_CREATE_FLOW` → on completion:
     install `rx_rings[{pid,fd}]` **then** `EPS_BIND_CONN{flow, pid, fd}`
     (that order — parked RX flushes the instant BIND lands).
   - `EPS_NEW_FLOW{flow}` → match listener by `flow.src` (local endpoint),
     run existing accept brokering (install accepted rx_ring, wake parked
     accept) → `EPS_BIND_CONN{flow verbatim, pid, accepted_fd}`. **Must be
     idempotent** — events re-post ~1/s until bound.
   - FORK → for each mirrored connection, additionally
     `EPS_BIND_CONN{same flow, child_pid, fd}` (engine keys strictly by
     {pid,fd}; child sends are held-unbound otherwise).
   - TEARDOWN → existing cleanup + `EPS_UNBIND_CONN{pid, fd}`.
6. **Retire the poller data path** for EPS-channel mode. The engine now also
   wakes `tx_blocked` senders — do not run both wakers.

## 7. Gotchas — the list that will save you a day each

1. **ABI**: `MachnetCtrlQueueEntry_t` and `machnet_channel_info_t` grew.
   Rebuild machnet + shim + daemon from the same tree, always. Mixed
   versions misparse ctrl rings / the controller socket.
2. **Flow orientation**: `eps_bind.flow` is TX orientation (src = local
   Machnet endpoint = `machnet_connect` result verbatim; NEW_FLOW arrives
   pre-swapped). Getting this backwards silently blackholes one direction.
3. **The flow's local port is Machnet-allocated**, not the app's port. Never
   derive routing from the app's port for outbound connections.
4. **Hold-slot head-of-line**: an unbound conn_key's tx_ring record blocks
   everything behind it until BIND. Send BIND promptly after connect
   completion; watch the `tx_held` stat (1/min log line).
5. **One eventfd token per delivered message, after submit** — the EPS
   semaphore invariant. The engine preserves it; don't add extra writers.
   Sender-wake tokens (tx_blocked) are absorbed as spurious wakes by design.
6. **First-ever record after switchover**: the tx_reader seeds from the
   published `consumer_pos`, so a cleanly stopped poller hands over
   mid-stream correctly. A poller killed mid-record does not — reload the
   BPF object (fresh rings) when switching modes.
7. **1500 B cap** both directions (EPS record format). Oversize reassembled
   messages are dropped and counted (`rx_oversize`).
8. **~1 s ctrl latency** is the engine slow tick (`kSlowTimerIntervalUs`,
   `machnet_engine.h:353`), not a bug. Shorten it there if setup latency
   matters (engine-wide implications: RTO granularity, status dumps).
9. **DESTROY_FLOW is a stub** (pre-existing): UNBIND cleans the EPS side;
   the Machnet flow lingers until the idle reaper. TCP CloseWait leak is a
   known TCP-branch issue.
10. **Stats are your debug window**: `EpsChannel` logs a per-minute line —
    `tx_converted / tx_held / tx_malformed / rx_delivered / rx_ring_full /
    rx_oversize / rx_no_conn / rx_pending / rx_expired`. First e2e triage
    starts there.

## 8. Test plan from here

| Stage | What | Pass criterion |
|---|---|---|
| 1 | `ctest -R eps_ring_test` on Linux | 8/8 (already green on macOS) |
| 2 | Full build + existing test suite | no regressions from the seam (`channel_test`, `flow_test`, `machnet_engine_test`) |
| 3 | Attach probe (§5) | EPS channel created, `InitEps` log line |
| 4 | Manual BIND + loopback-free echo: daemon stub binds a conn to a flow between two hosts running machnet; `app_a`/`app_b` from the EPS repo | request/response completes; stats clean |
| 5 | Full daemon integration (§6), `demo.sh` scenario cross-host | unmodified POSIX apps communicate over DPDK |
| 6 | Soak + adversarial: kill daemon mid-traffic (established flows must keep running), fd-reuse churn, rx_ring-full backpressure, fork | no leaks (`GetFreeBufCount` stable), no wedged rings |

## 9. Open decisions (parked deliberately)

- Rebase onto `tcp-handshake-csum` vs. first smoke on mlx5 vs. UDP-flows
  first (§3).
- Ctrl-tick shortening for connection-setup latency.
- >1500 B messages (needs EPS-side segmentation).
- Multi-engine support (blocked on the static `engine_index` bug +
  per-ring single-producer constraint).
- Real DESTROY_FLOW (benefits non-EPS Machnet too).

## 10. Artifact & reference index

- Code: branch `eps-option-b`, commit `33fa678` (14 files, +2151/−15).
- In-repo docs: `docs/EPS_DESIGN.md`, `docs/EPS.md`, this file.
- Published (private) artifact pages: design doc and contract are on
  claude.ai/code/artifacts (owner: sarsanaee).
- EPS reference sources this was written against:
  `Accelerated_Networking-main/accelerated/src/{poller.c, eps_hooks.bpf.c,
  daemon.c, ctx.h}` — note the local snapshot **predates Option A**; the
  live EPS tree has diverged, so re-verify `control_event`/`tx_entry`
  layouts against the deployed BPF object before first run (the
  `static_assert`s in `eps_ring.h` catch payload-size drift at compile time
  only if the headers are updated to match).
- TCP branch review context: PR #54 findings, fix PRs #55/#56 (branches
  `tcp-retransmit-wnd`, `tcp-handshake-csum`) — also not yet compiled on a
  DPDK host.

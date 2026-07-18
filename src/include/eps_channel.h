/**
 * @file eps_channel.h
 *
 * EPS-backed Machnet channel.
 *
 * `EpsChannel' is an alternative channel backend that connects the Machnet
 * engine directly to the EPS eBPF datapath ("Accelerated Networking"):
 *
 *   - TX intake: instead of dequeuing app messages from the channel's
 *     App->Machnet shm ring, the engine drains the EPS kernel `tx_ring'
 *     (BPF_MAP_TYPE_RINGBUF) that the eBPF sendto() hook fills, converting
 *     each record into a `MsgBuf' chain (see `DequeueMessages').
 *   - RX delivery: instead of enqueuing completed messages onto the
 *     Machnet->App shm ring, the engine writes them into the destination
 *     connection's `rx_ring' (BPF_MAP_TYPE_USER_RINGBUF inner map of the
 *     `rx_rings' hash-of-maps) and wakes the receiver's eventfd (see
 *     `EnqueueMessages').
 *
 * The channel's shm segment is still fully allocated and used as the engine's
 * buffer pool (and for the ctrl SQ/CQ rings); only the two message rings are
 * bypassed. Routing policy is *not* decided here: the EPS daemon binds EPS
 * connections (conn_key = {pid, fd}) to Machnet flows with
 * MACHNET_CTRL_OP_EPS_BIND_CONN control requests, and learns about unbound
 * inbound flows via MACHNET_CTRL_OP_EPS_NEW_FLOW completions.
 *
 * Threading: all methods (including the overridden seam methods) must be
 * called from the engine thread that owns this channel — the same discipline
 * the rest of the engine already follows. The libbpf user_ring_buffer
 * producer API is not thread-safe.
 */
#ifndef SRC_INCLUDE_EPS_CHANNEL_H_
#define SRC_INCLUDE_EPS_CHANNEL_H_

#include <channel.h>
#include <eps_ring.h>

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

// Forward declaration of the libbpf user ring buffer handle, so that this
// header does not require libbpf headers (they are only needed in
// eps_channel.cc).
struct user_ring_buffer;

namespace juggler {
namespace shm {

#ifdef MACHNET_EPS_ENABLED

/**
 * @brief Machnet channel backend that speaks the EPS eBPF datapath.
 * See the file-level comment for the overall design.
 */
class EpsChannel : public Channel {
 public:
  static constexpr const char *kDefaultBpfPinDir = "/sys/fs/bpf/accelerated";
  // Environment variable that overrides the BPF pin directory.
  static constexpr const char *kBpfPinDirEnvVar = "MACHNET_EPS_BPF_DIR";

  // Bounds for internal queues (all counted in messages).
  static constexpr size_t kMaxPendingRxMessages = 256;
  static constexpr uint32_t kPendingRxMaxSweeps = 8;
  static constexpr size_t kMaxCtrlOutQueue = 128;
  // Bounded wait for space in a full rx_ring before dropping the message.
  static constexpr int kRxRingReserveRetries = 256;
  // Under sustained tx_ring backpressure, wake parked senders every this
  // many drained records (poller parity).
  static constexpr uint32_t kTxWakeBatchThreshold = 64;

  struct EpsStats {
    uint64_t tx_records_converted{0};
    uint64_t tx_records_malformed{0};
    uint64_t tx_records_held_unbound{0};  // held head-of-line: no BIND yet
    uint64_t rx_delivered{0};
    uint64_t rx_dropped_ring_full{0};
    uint64_t rx_dropped_oversize{0};
    uint64_t rx_dropped_no_conn{0};
    uint64_t rx_pending{0};
    uint64_t rx_pending_expired{0};
  };

  EpsChannel(const std::string &name, const MachnetChannelCtx_t *ctx,
             const size_t channel_mem_size, const bool is_posix_shm,
             int channel_fd, std::string bpf_pin_dir = BpfPinDirFromEnv());
  ~EpsChannel() override;

  EpsChannel(const EpsChannel &) = delete;
  EpsChannel &operator=(const EpsChannel &) = delete;

  // Resolve the BPF pin directory: $MACHNET_EPS_BPF_DIR or the default.
  static std::string BpfPinDirFromEnv();

  /**
   * @brief Open the pinned EPS maps and mmap the tx_ring. Must be called
   * (successfully) before the channel is handed to an engine; until then the
   * overridden seam methods behave as no-ops.
   * @return true on success.
   */
  bool InitEps();

  bool IsEpsReady() const { return eps_ready_; }
  const EpsStats &GetEpsStats() const { return stats_; }

  /**
   * @brief RX delivery seam: write each completed message into the bound EPS
   * connection's rx_ring and wake its eventfd.
   *
   * Always reports all messages as consumed: ownership of the buffer chains
   * transfers to this method, which either delivers and frees them, parks
   * them until a BIND_CONN arrives for their flow, or drops and frees them
   * (full ring / oversize / unknown connection). Returning anything less
   * than `nb_msgs' would be treated as a fatal error by the UDP flow path.
   */
  uint32_t EnqueueMessages(MsgBuf *const *msgs, uint32_t nb_msgs) override;

  /**
   * @brief TX intake seam: drain the EPS tx_ring, converting records into
   * `MsgBuf' chains stamped with the flow bound to the record's conn_key.
   *
   * Records whose conn_key has no bound flow yet are held in the ring
   * (consumer position is not advanced), mirroring the EPS poller's
   * hold-slot backpressure. Buffer-pool exhaustion likewise leaves the
   * record in the ring for the next call.
   */
  uint32_t DequeueMessages(MachnetRingSlot_t *msg_indices, MsgBuf **msgs,
                           uint32_t nb_msgs) override;

  /**
   * @brief Ctrl seam: consume EPS-specific opcodes (BIND_CONN/UNBIND_CONN)
   * internally and pass every other request through to the engine. Also
   * piggybacks periodic maintenance (sweep, deferred CQ posts), since the
   * engine calls this on its slow tick.
   */
  uint32_t DequeueCtrlRequests(MachnetCtrlQueueEntry_t *ctrl_entries,
                               uint32_t nb_entries) override;

  // Keep the hidden base-class overloads visible on the derived type.
  using ShmChannel::DequeueMessages;
  using ShmChannel::EnqueueMessages;

 private:
  // A network flow endpoint pair, used as a routing key. For RX routing the
  // tuple is in "delivery orientation" (src = remote peer, dst = local
  // Machnet endpoint), matching `MsgBuf::flow()' of delivered messages.
  struct EpsFlowTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const EpsFlowTuple &o) const {
      return src_ip == o.src_ip && dst_ip == o.dst_ip &&
             src_port == o.src_port && dst_port == o.dst_port;
    }
    static EpsFlowTuple FromFlow(const MachnetFlow_t &flow) {
      return EpsFlowTuple{flow.src_ip, flow.dst_ip, flow.src_port,
                          flow.dst_port};
    }
    EpsFlowTuple Reversed() const {
      return EpsFlowTuple{dst_ip, src_ip, dst_port, src_port};
    }
    MachnetFlow_t ToFlow() const {
      MachnetFlow_t flow;
      flow.src_ip = src_ip;
      flow.dst_ip = dst_ip;
      flow.src_port = src_port;
      flow.dst_port = dst_port;
      return flow;
    }
  };

  struct EpsFlowTupleHash {
    size_t operator()(const EpsFlowTuple &t) const {
      const uint64_t a =
          (static_cast<uint64_t>(t.src_ip) << 32) | t.dst_ip;
      const uint64_t b =
          (static_cast<uint64_t>(t.src_port) << 16) | t.dst_port;
      return std::hash<uint64_t>{}(a ^ (b * 0x9E3779B97F4A7C15ULL));
    }
  };

  // Cached handle to one EPS connection's rx_ring (USER_RINGBUF inner map)
  // and receiver-wake eventfd.
  struct RxConn {
    int map_fd{-1};
    struct user_ring_buffer *ring{nullptr};
    int wake_efd{-1};  // dup'ed via pidfd_getfd; -1 until acquired
    // Inner map ID this handle was opened from; used to detect the daemon
    // replacing a connection's ring (e.g., after {pid, fd} reuse).
    uint32_t inner_map_id{0};
  };

  // Messages parked while waiting for a BIND_CONN of their flow.
  struct PendingRx {
    std::vector<MsgBuf *> msgs;
    uint32_t sweeps{0};
  };

  static uint64_t PackConnKey(const EpsConnKey &key) {
    return (static_cast<uint64_t>(key.pid) << 32) | key.fd;
  }
  static EpsConnKey UnpackConnKey(uint64_t packed) {
    return EpsConnKey{static_cast<uint32_t>(packed >> 32),
                      static_cast<uint32_t>(packed & 0xFFFFFFFFu)};
  }

  // --- Ctrl-plane handlers (engine slow tick) ---
  void HandleBindConn(const MachnetCtrlQueueEntry_t &req);
  void HandleUnbindConn(const MachnetCtrlQueueEntry_t &req);
  void PostCtrlCompletion(uint64_t id, bool success);
  void PostNewFlowEvent(const EpsFlowTuple &tx_orient_tuple);
  void TryFlushCtrlOut();
  void Sweep();
  void EvictRxConn(uint64_t conn_key);

  // Wake senders parked in a blocking sendto() because the tx_ring was full
  // (they are recorded in the EPS `tx_blocked' map). Draining the tx_ring is
  // now the engine's job, so waking them is too (the poller used to do it).
  void WakeParkedSenders();

  // --- RX delivery helpers ---
  void DeliverMessage(MsgBuf *head);
  bool DeliverToRing(RxConn *conn, MsgBuf *head, uint32_t total_len);
  RxConn *EnsureRxConn(uint64_t conn_key);
  void EnsureWakeEfd(RxConn *conn, const EpsConnKey &key);
  void ParkUnroutable(const EpsFlowTuple &rx_tuple, MsgBuf *head);
  void FlushPendingFor(const EpsFlowTuple &rx_tuple);
  uint32_t ChainDataLen(const MsgBuf *head);
  void FreeChain(MsgBuf *head);

  // --- TX intake helpers ---
  MsgBuf *BuildMsgChain(const uint8_t *data, uint32_t len,
                        const MachnetFlow_t &flow);

  const std::string bpf_pin_dir_;
  bool eps_ready_{false};

  // tx_ring state.
  int tx_ring_fd_{-1};
  size_t tx_ring_data_size_{0};
  long page_size_{0};
  void *tx_cons_map_{nullptr};
  void *tx_prod_map_{nullptr};
  void *tx_data_map_{nullptr};
  EpsTxRingReader tx_reader_;

  // rx_rings (hash-of-maps) fd.
  int rx_rings_fd_{-1};
  // tx_blocked (parked senders) fd; -1 when the pin is absent (wake is then
  // a no-op, matching the poller's optional handling).
  int tx_blocked_fd_{-1};
  // Records drained since the last parked-sender wake pass.
  uint32_t tx_drained_since_wake_{0};

  // conn_key -> rx_ring handle.
  std::unordered_map<uint64_t, RxConn> rx_conns_;
  // conn_key -> Machnet flow in TX orientation (src = local endpoint).
  std::unordered_map<uint64_t, MachnetFlow_t> tx_flows_;
  // Delivery-orientation tuple -> conn_key.
  std::unordered_map<EpsFlowTuple, uint64_t, EpsFlowTupleHash> rx_routes_;
  // Delivery-orientation tuple -> messages parked until BIND_CONN.
  std::unordered_map<EpsFlowTuple, PendingRx, EpsFlowTupleHash> pending_rx_;
  size_t pending_rx_count_{0};
  // TX-orientation tuples for which a NEW_FLOW event was already queued.
  std::unordered_map<EpsFlowTuple, bool, EpsFlowTupleHash> new_flow_posted_;
  // Deferred ctrl CQ entries (completions + NEW_FLOW events); the CQ ring is
  // tiny, so entries that do not fit are retried on the next slow tick.
  std::deque<MachnetCtrlQueueEntry_t> ctrl_out_queue_;

  EpsStats stats_;
};

#endif  // MACHNET_EPS_ENABLED

}  // namespace shm
}  // namespace juggler

#endif  // SRC_INCLUDE_EPS_CHANNEL_H_

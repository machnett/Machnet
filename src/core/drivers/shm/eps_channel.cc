/**
 * @file eps_channel.cc
 *
 * Implementation of `EpsChannel' — the Machnet channel backend that drains
 * the EPS eBPF tx_ring and delivers received messages into per-connection
 * USER_RINGBUF rx_rings. See eps_channel.h for the design overview.
 */
#include <eps_channel.h>

#ifdef MACHNET_EPS_ENABLED

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <glog/logging.h>
#include <pause.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <utility>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

namespace juggler {
namespace shm {

namespace {

// Offset of the payload within an EPS tx_ring record.
constexpr uint32_t kEpsTxEntryHdrSize = offsetof(EpsTxEntry, data);
static_assert(kEpsTxEntryHdrSize == 12, "EpsTxEntry header ABI mismatch");

int PidfdGetFd(uint32_t pid, uint32_t fd) {
  const int pidfd =
      static_cast<int>(syscall(SYS_pidfd_open, static_cast<pid_t>(pid), 0));
  if (pidfd < 0) return -1;
  const int dup_fd = static_cast<int>(
      syscall(SYS_pidfd_getfd, pidfd, static_cast<int>(fd), 0));
  close(pidfd);
  return dup_fd;
}

}  // namespace

EpsChannel::EpsChannel(const std::string &name,
                       const MachnetChannelCtx_t *ctx,
                       const size_t channel_mem_size, const bool is_posix_shm,
                       int channel_fd, std::string bpf_pin_dir)
    : Channel(name, ctx, channel_mem_size, is_posix_shm, channel_fd),
      bpf_pin_dir_(std::move(bpf_pin_dir)) {}

EpsChannel::~EpsChannel() {
  for (auto &conn_entry : rx_conns_) {
    auto &conn = conn_entry.second;
    if (conn.ring != nullptr) user_ring_buffer__free(conn.ring);
    if (conn.map_fd >= 0) close(conn.map_fd);
    if (conn.wake_efd >= 0) close(conn.wake_efd);
  }
  rx_conns_.clear();

  // Parked messages point into the channel's shm segment, which is destroyed
  // by the base class; no per-buffer cleanup is needed here.
  LOG_IF(WARNING, pending_rx_count_ > 0)
      << "EpsChannel " << GetName() << " destroyed with " << pending_rx_count_
      << " undelivered parked message(s).";

  if (tx_cons_map_ != nullptr) munmap(tx_cons_map_, page_size_);
  if (tx_prod_map_ != nullptr) munmap(tx_prod_map_, page_size_);
  if (tx_data_map_ != nullptr) munmap(tx_data_map_, 2 * tx_ring_data_size_);
  tx_cons_map_ = tx_prod_map_ = tx_data_map_ = nullptr;
  if (tx_ring_fd_ >= 0) close(tx_ring_fd_);
  if (rx_rings_fd_ >= 0) close(rx_rings_fd_);
  if (tx_blocked_fd_ >= 0) close(tx_blocked_fd_);
  tx_ring_fd_ = rx_rings_fd_ = tx_blocked_fd_ = -1;
  eps_ready_ = false;
}

std::string EpsChannel::BpfPinDirFromEnv() {
  const char *dir = getenv(kBpfPinDirEnvVar);
  return (dir != nullptr && dir[0] != '\0') ? std::string(dir)
                                            : std::string(kDefaultBpfPinDir);
}

bool EpsChannel::InitEps() {
  if (eps_ready_) return true;

  page_size_ = sysconf(_SC_PAGESIZE);

  const std::string tx_path = bpf_pin_dir_ + "/tx_ring";
  tx_ring_fd_ = bpf_obj_get(tx_path.c_str());
  if (tx_ring_fd_ < 0) {
    const int err = errno;
    LOG(ERROR) << "EpsChannel: bpf_obj_get(" << tx_path
               << ") failed: " << strerror(err);
    return false;
  }

  const std::string rx_path = bpf_pin_dir_ + "/rx_rings";
  rx_rings_fd_ = bpf_obj_get(rx_path.c_str());
  if (rx_rings_fd_ < 0) {
    const int err = errno;
    LOG(ERROR) << "EpsChannel: bpf_obj_get(" << rx_path
               << ") failed: " << strerror(err);
    return false;
  }

  // Optional: senders parked on a full tx_ring. Absence is non-fatal
  // (blocking-sender wake is then disabled), matching the EPS poller.
  const std::string tx_blocked_path = bpf_pin_dir_ + "/tx_blocked";
  tx_blocked_fd_ = bpf_obj_get(tx_blocked_path.c_str());
  LOG_IF(WARNING, tx_blocked_fd_ < 0)
      << "EpsChannel: tx_blocked pin not found; blocking-sender wake "
         "disabled.";

  struct bpf_map_info info;
  memset(&info, 0, sizeof(info));
  __u32 info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(tx_ring_fd_, &info, &info_len) != 0) {
    LOG(ERROR) << "EpsChannel: bpf_obj_get_info_by_fd(tx_ring) failed: "
               << strerror(errno);
    return false;
  }
  tx_ring_data_size_ = info.max_entries;
  if (tx_ring_data_size_ == 0 ||
      (tx_ring_data_size_ & (tx_ring_data_size_ - 1)) != 0) {
    LOG(ERROR) << "EpsChannel: tx_ring size " << tx_ring_data_size_
               << " is not a power of two.";
    return false;
  }

  // BPF ringbuf mmap layout: [consumer page][producer page][data x2].
  void *cons = mmap(nullptr, page_size_, PROT_READ | PROT_WRITE, MAP_SHARED,
                    tx_ring_fd_, 0);
  if (cons == MAP_FAILED) {
    LOG(ERROR) << "EpsChannel: mmap(tx_ring consumer) failed: "
               << strerror(errno);
    return false;
  }
  tx_cons_map_ = cons;

  void *prod =
      mmap(nullptr, page_size_, PROT_READ, MAP_SHARED, tx_ring_fd_,
           page_size_);
  if (prod == MAP_FAILED) {
    LOG(ERROR) << "EpsChannel: mmap(tx_ring producer) failed: "
               << strerror(errno);
    return false;
  }
  tx_prod_map_ = prod;

  void *data = mmap(nullptr, 2 * tx_ring_data_size_, PROT_READ, MAP_SHARED,
                    tx_ring_fd_, 2 * page_size_);
  if (data == MAP_FAILED) {
    LOG(ERROR) << "EpsChannel: mmap(tx_ring data) failed: " << strerror(errno);
    return false;
  }
  tx_data_map_ = data;

  tx_reader_.Init(static_cast<volatile uint64_t *>(tx_cons_map_),
                  static_cast<const volatile uint64_t *>(tx_prod_map_),
                  static_cast<const uint8_t *>(tx_data_map_),
                  tx_ring_data_size_);

  eps_ready_ = true;
  LOG(INFO) << "EpsChannel " << GetName() << " attached to EPS datapath (pin "
            << "dir: " << bpf_pin_dir_ << ", tx_ring: " << tx_ring_data_size_
            << " bytes, consumer offset: " << tx_reader_.consumer_offset()
            << ").";
  return true;
}

// ---------------------------------------------------------------------------
// TX intake: EPS tx_ring -> MsgBuf chains for the engine.
// ---------------------------------------------------------------------------

MsgBuf *EpsChannel::BuildMsgChain(const uint8_t *data, uint32_t len,
                                  const MachnetFlow_t &flow) {
  const uint32_t mss = GetUsableBufSize();
  DCHECK_GT(mss, 0u);
  const uint32_t nbufs = (len + mss - 1) / mss;

  // With len <= kEpsMaxPayload (1500) and MTU-sized channel buffers, a
  // message spans at most a couple of buffers; 8 is a generous static bound.
  constexpr uint32_t kMaxChainBufs = 8;
  if (nbufs == 0 || nbufs > kMaxChainBufs) {
    LOG_EVERY_N(ERROR, 1024)
        << "EpsChannel: cannot fit " << len << "-byte record in "
        << kMaxChainBufs << " buffers (mss: " << mss << ").";
    return nullptr;
  }

  MsgBuf *bufs[kMaxChainBufs];
  for (uint32_t i = 0; i < nbufs; i++) {
    bufs[i] = MsgBufAlloc();
    if (bufs[i] == nullptr) {
      // Pool exhausted: back out and let the caller retry the record later.
      for (uint32_t j = 0; j < i; j++) MsgBufFree(bufs[j]);
      return nullptr;
    }
  }

  uint32_t ofs = 0;
  for (uint32_t i = 0; i < nbufs; i++) {
    const uint32_t chunk = std::min(mss, len - ofs);
    auto *dst = bufs[i]->append<uint8_t *>(chunk);
    DCHECK(dst != nullptr);
    memcpy(dst, data + ofs, chunk);
    ofs += chunk;
    if (i + 1 < nbufs) bufs[i]->set_next(bufs[i + 1]);  // Also sets SG.
  }
  DCHECK_EQ(ofs, len);

  MsgBuf *head = bufs[0];
  MsgBuf *tail = bufs[nbufs - 1];
  head->mark_first();
  tail->mark_last();
  head->set_msg_length(len);
  head->set_last(GetBufIndex(tail));
  head->set_src_ip(flow.src_ip);
  head->set_src_port(flow.src_port);
  head->set_dst_ip(flow.dst_ip);
  head->set_dst_port(flow.dst_port);
  return head;
}

uint32_t EpsChannel::DequeueMessages(MachnetRingSlot_t *msg_indices,
                                     MsgBuf **msgs, uint32_t nb_msgs) {
  if (!eps_ready_) return 0;

  uint32_t out = 0;
  while (out < nb_msgs) {
    const uint8_t *payload = nullptr;
    uint32_t rec_len = 0;
    const auto status = tx_reader_.Peek(&payload, &rec_len);
    if (status == EpsTxRingReader::Status::kEmpty ||
        status == EpsTxRingReader::Status::kBusy)
      break;
    if (status == EpsTxRingReader::Status::kDiscard) {
      tx_reader_.Advance(rec_len);
      continue;
    }

    // A committed record.
    if (rec_len < kEpsTxEntryHdrSize) {
      stats_.tx_records_malformed++;
      LOG_EVERY_N(ERROR, 1024)
          << "EpsChannel: malformed tx_ring record (len " << rec_len << ").";
      tx_reader_.Advance(rec_len);
      continue;
    }
    const auto *entry = reinterpret_cast<const EpsTxEntry *>(payload);
    const uint32_t payload_len = entry->len;
    if (payload_len == 0 || payload_len > kEpsMaxPayload ||
        payload_len > rec_len - kEpsTxEntryHdrSize) {
      stats_.tx_records_malformed++;
      LOG_EVERY_N(ERROR, 1024)
          << "EpsChannel: malformed tx_ring payload length " << payload_len
          << " (record " << rec_len << " bytes).";
      tx_reader_.Advance(rec_len);
      continue;
    }

    const auto flow_it = tx_flows_.find(PackConnKey(entry->conn_key));
    if (flow_it == tx_flows_.end()) {
      // No BIND_CONN for this connection yet: hold the record in the ring
      // (do not advance), mirroring the EPS poller's hold-slot behavior.
      // NOTE: this head-of-line blocks records behind it until the daemon
      // binds the connection.
      stats_.tx_records_held_unbound++;
      LOG_EVERY_N(WARNING, 1024)
          << "EpsChannel: holding tx_ring record for unbound EPS connection "
          << "{pid: " << entry->conn_key.pid << ", fd: " << entry->conn_key.fd
          << "}.";
      break;
    }

    MsgBuf *head = BuildMsgChain(entry->data, payload_len, flow_it->second);
    if (head == nullptr) break;  // Pool exhausted: retry this record later.

    msg_indices[out] = GetBufIndex(head);
    msgs[out] = head;
    out++;
    stats_.tx_records_converted++;
    tx_reader_.Advance(rec_len);
  }

  // Draining freed tx_ring space: wake senders parked on a full ring. Wake
  // on drain-to-empty, or every kTxWakeBatchThreshold records under
  // sustained backpressure (poller parity).
  if (out > 0) tx_drained_since_wake_ += out;
  if (tx_drained_since_wake_ > 0) {
    const uint8_t *peek_payload = nullptr;
    uint32_t peek_len = 0;
    if (tx_drained_since_wake_ >= kTxWakeBatchThreshold ||
        tx_reader_.Peek(&peek_payload, &peek_len) ==
            EpsTxRingReader::Status::kEmpty) {
      WakeParkedSenders();
    }
  }

  return out;
}

void EpsChannel::WakeParkedSenders() {
  tx_drained_since_wake_ = 0;
  if (tx_blocked_fd_ < 0) return;

  EpsConnKey key;
  // Common case: no parked senders — one syscall returning ENOENT.
  if (bpf_map_get_next_key(tx_blocked_fd_, nullptr, &key) != 0) return;

  // Edge-triggered like the poller: wake and delete each entry. A woken
  // sender that still finds the ring full re-parks itself (BPF side), so no
  // wakeup is lost.
  while (true) {
    EpsConnKey next;
    const bool have_next =
        (bpf_map_get_next_key(tx_blocked_fd_, &key, &next) == 0);

    const int sender_efd = PidfdGetFd(key.pid, key.fd);
    if (sender_efd >= 0) {
      const uint64_t one = 1;
      const ssize_t ret = write(sender_efd, &one, sizeof(one));
      (void)ret;
      close(sender_efd);
    }
    bpf_map_delete_elem(tx_blocked_fd_, &key);

    if (!have_next) break;
    key = next;
  }
}

// ---------------------------------------------------------------------------
// RX delivery: MsgBuf chains -> per-connection USER_RINGBUF + eventfd wake.
// ---------------------------------------------------------------------------

uint32_t EpsChannel::ChainDataLen(const MsgBuf *head) {
  uint32_t total = 0;
  uint32_t guard = GetTotalBufCount();
  const MsgBuf *cur = head;
  while (cur != nullptr && guard-- > 0) {
    total += cur->length();
    if (!cur->has_next()) break;
    cur = GetMsgBuf(cur->next());
  }
  return total;
}

void EpsChannel::FreeChain(MsgBuf *head) {
  MachnetRingSlot_t indices[MsgBufBatch::kMaxBurst];
  uint32_t cnt = 0;
  uint32_t guard = GetTotalBufCount();
  MsgBuf *cur = head;
  while (cur != nullptr && guard-- > 0) {
    indices[cnt++] = GetBufIndex(cur);
    MsgBuf *next =
        cur->has_next() ? GetMsgBuf(cur->next()) : nullptr;
    if (cnt == MsgBufBatch::kMaxBurst) {
      MsgBufBulkFree(indices, cnt);
      cnt = 0;
    }
    cur = next;
  }
  if (cnt > 0) MsgBufBulkFree(indices, cnt);
}

EpsChannel::RxConn *EpsChannel::EnsureRxConn(uint64_t conn_key) {
  const auto it = rx_conns_.find(conn_key);
  if (it != rx_conns_.end()) return &it->second;

  EpsConnKey raw = UnpackConnKey(conn_key);
  uint32_t inner_map_id = 0;
  if (bpf_map_lookup_elem(rx_rings_fd_, &raw, &inner_map_id) != 0) {
    // The daemon has not installed (or has torn down) this connection's
    // rx_ring.
    return nullptr;
  }

  const int inner_fd = bpf_map_get_fd_by_id(inner_map_id);
  if (inner_fd < 0) {
    LOG_EVERY_N(WARNING, 256)
        << "EpsChannel: bpf_map_get_fd_by_id(" << inner_map_id
        << ") failed: " << strerror(errno);
    return nullptr;
  }

  struct user_ring_buffer *ring = user_ring_buffer__new(inner_fd, nullptr);
  if (ring == nullptr) {
    LOG_EVERY_N(WARNING, 256)
        << "EpsChannel: user_ring_buffer__new(map id " << inner_map_id
        << ") failed: " << strerror(errno);
    close(inner_fd);
    return nullptr;
  }

  const auto ins =
      rx_conns_.emplace(conn_key, RxConn{inner_fd, ring, -1, inner_map_id});
  return &ins.first->second;
}

void EpsChannel::EnsureWakeEfd(RxConn *conn, const EpsConnKey &key) {
  if (conn->wake_efd >= 0) return;
  conn->wake_efd = PidfdGetFd(key.pid, key.fd);
  LOG_IF_EVERY_N(WARNING, conn->wake_efd < 0, 256)
      << "EpsChannel: pidfd_getfd(pid " << key.pid << ", fd " << key.fd
      << ") failed: " << strerror(errno);
}

bool EpsChannel::DeliverToRing(RxConn *conn, MsgBuf *head,
                               uint32_t total_len) {
  const uint32_t sample_len = sizeof(uint32_t) + total_len;
  void *slot = nullptr;
  int retries = kRxRingReserveRetries;
  while ((slot = user_ring_buffer__reserve(conn->ring, sample_len)) ==
         nullptr) {
    if (errno != ENOSPC && errno != EAGAIN) {
      LOG_EVERY_N(WARNING, 256)
          << "EpsChannel: user_ring_buffer__reserve(" << sample_len
          << ") failed: " << strerror(errno);
      return false;
    }
    if (--retries <= 0) return false;  // Ring full: give up, caller drops.
    machnet_pause();
  }

  // Sample format expected by the eBPF read()-exit drain callback:
  // [u32 total_len][total_len bytes of payload].
  memcpy(slot, &total_len, sizeof(uint32_t));
  uint8_t *dst = static_cast<uint8_t *>(slot) + sizeof(uint32_t);
  uint32_t guard = GetTotalBufCount();
  MsgBuf *cur = head;
  while (cur != nullptr && guard-- > 0) {
    memcpy(dst, cur->head_data<uint8_t *>(), cur->length());
    dst += cur->length();
    if (!cur->has_next()) break;
    cur = GetMsgBuf(cur->next());
  }

  user_ring_buffer__submit(conn->ring, slot);
  return true;
}

void EpsChannel::ParkUnroutable(const EpsFlowTuple &rx_tuple, MsgBuf *head) {
  // Tell the daemon about this flow (in TX orientation, so it can echo the
  // tuple back verbatim in a BIND_CONN request).
  PostNewFlowEvent(rx_tuple.Reversed());

  if (pending_rx_count_ >= kMaxPendingRxMessages) {
    stats_.rx_dropped_no_conn++;
    LOG_EVERY_N(WARNING, 256)
        << "EpsChannel: pending-RX limit reached; dropping message for "
        << "unbound flow.";
    FreeChain(head);
    return;
  }

  auto &pending = pending_rx_[rx_tuple];
  pending.sweeps = 0;
  pending.msgs.push_back(head);
  pending_rx_count_++;
  stats_.rx_pending = pending_rx_count_;
}

void EpsChannel::DeliverMessage(MsgBuf *head) {
  const MachnetFlow_t *flow = head->flow();
  const EpsFlowTuple rx_tuple = EpsFlowTuple::FromFlow(*flow);

  const auto route_it = rx_routes_.find(rx_tuple);
  if (route_it == rx_routes_.end()) {
    ParkUnroutable(rx_tuple, head);
    return;
  }
  const uint64_t conn_key = route_it->second;

  const uint32_t total_len = ChainDataLen(head);
  if (total_len == 0 || total_len > kEpsMaxPayload) {
    stats_.rx_dropped_oversize++;
    LOG_EVERY_N(WARNING, 256)
        << "EpsChannel: dropping " << total_len
        << "-byte message (EPS record limit is " << kEpsMaxPayload << ").";
    FreeChain(head);
    return;
  }

  RxConn *conn = EnsureRxConn(conn_key);
  if (conn == nullptr) {
    stats_.rx_dropped_no_conn++;
    FreeChain(head);
    return;
  }

  if (DeliverToRing(conn, head, total_len)) {
    stats_.rx_delivered++;
    // Semaphore protocol: exactly one eventfd token per delivered message,
    // written AFTER the ring submit.
    EnsureWakeEfd(conn, UnpackConnKey(conn_key));
    if (conn->wake_efd >= 0) {
      const uint64_t one = 1;
      const ssize_t ret = write(conn->wake_efd, &one, sizeof(one));
      LOG_IF_EVERY_N(WARNING, ret != sizeof(one), 256)
          << "EpsChannel: eventfd wake write failed: " << strerror(errno);
    }
  } else {
    stats_.rx_dropped_ring_full++;
  }

  FreeChain(head);
}

uint32_t EpsChannel::EnqueueMessages(MsgBuf *const *msgs, uint32_t nb_msgs) {
  for (uint32_t i = 0; i < nb_msgs; i++) {
    MsgBuf *head = msgs[i];
    if (head == nullptr) continue;
    if (!eps_ready_) {
      stats_.rx_dropped_no_conn++;
      FreeChain(head);
      continue;
    }
    DeliverMessage(head);
  }
  // Ownership of all chains was taken (delivered, parked, or dropped).
  return nb_msgs;
}

// ---------------------------------------------------------------------------
// Ctrl plane: BIND/UNBIND interception, NEW_FLOW events, sweep.
// ---------------------------------------------------------------------------

void EpsChannel::TryFlushCtrlOut() {
  while (!ctrl_out_queue_.empty()) {
    if (EnqueueCtrlCompletions(&ctrl_out_queue_.front(), 1) != 1) break;
    ctrl_out_queue_.pop_front();
  }
}

void EpsChannel::PostCtrlCompletion(uint64_t id, bool success) {
  MachnetCtrlQueueEntry_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.id = id;
  resp.opcode = MACHNET_CTRL_OP_STATUS;
  resp.status =
      success ? MACHNET_CTRL_STATUS_OK : MACHNET_CTRL_STATUS_ERROR;
  if (ctrl_out_queue_.size() >= kMaxCtrlOutQueue) {
    LOG(WARNING) << "EpsChannel: ctrl out-queue overflow; dropping oldest.";
    ctrl_out_queue_.pop_front();
  }
  ctrl_out_queue_.push_back(resp);
  TryFlushCtrlOut();
}

void EpsChannel::PostNewFlowEvent(const EpsFlowTuple &tx_orient_tuple) {
  if (new_flow_posted_.find(tx_orient_tuple) != new_flow_posted_.end())
    return;

  MachnetCtrlQueueEntry_t event;
  memset(&event, 0, sizeof(event));
  event.id = 0;
  event.opcode = MACHNET_CTRL_OP_EPS_NEW_FLOW;
  event.status = MACHNET_CTRL_STATUS_OK;
  event.eps_bind.flow = tx_orient_tuple.ToFlow();
  event.eps_bind.pid = 0;
  event.eps_bind.fd = 0;
  if (ctrl_out_queue_.size() >= kMaxCtrlOutQueue) {
    LOG(WARNING) << "EpsChannel: ctrl out-queue overflow; dropping oldest.";
    ctrl_out_queue_.pop_front();
  }
  ctrl_out_queue_.push_back(event);
  new_flow_posted_[tx_orient_tuple] = true;
  TryFlushCtrlOut();
}

void EpsChannel::FlushPendingFor(const EpsFlowTuple &rx_tuple) {
  const auto it = pending_rx_.find(rx_tuple);
  if (it == pending_rx_.end()) return;

  // Detach first: DeliverMessage may park again if delivery fails, and we
  // must not mutate the map mid-iteration.
  std::vector<MsgBuf *> msgs = std::move(it->second.msgs);
  pending_rx_.erase(it);
  DCHECK_GE(pending_rx_count_, msgs.size());
  pending_rx_count_ -= msgs.size();
  stats_.rx_pending = pending_rx_count_;

  for (auto *head : msgs) DeliverMessage(head);
}

void EpsChannel::HandleBindConn(const MachnetCtrlQueueEntry_t &req) {
  const MachnetEpsConnBind_t &bind = req.eps_bind;
  const EpsConnKey key{bind.pid, bind.fd};
  const uint64_t conn_key = PackConnKey(key);

  const EpsFlowTuple tx_tuple = EpsFlowTuple::FromFlow(bind.flow);
  const EpsFlowTuple rx_tuple = tx_tuple.Reversed();

  // A fresh bind may reuse a {pid, fd} whose previous incarnation is still
  // cached (fd numbers are per-process and recycled): drop any stale rx_ring
  // and eventfd handles so they are re-resolved on the next delivery.
  EvictRxConn(conn_key);

  tx_flows_[conn_key] = bind.flow;
  rx_routes_[rx_tuple] = conn_key;
  new_flow_posted_.erase(tx_tuple);

  LOG(INFO) << "EpsChannel: bound EPS connection {pid: " << bind.pid
            << ", fd: " << bind.fd << "} to flow "
            << net::Ipv4::Address(bind.flow.src_ip).ToString() << ":"
            << bind.flow.src_port << " -> "
            << net::Ipv4::Address(bind.flow.dst_ip).ToString() << ":"
            << bind.flow.dst_port;

  PostCtrlCompletion(req.id, true);
  FlushPendingFor(rx_tuple);
}

void EpsChannel::HandleUnbindConn(const MachnetCtrlQueueEntry_t &req) {
  const MachnetEpsConnBind_t &bind = req.eps_bind;
  const uint64_t conn_key = PackConnKey(EpsConnKey{bind.pid, bind.fd});

  tx_flows_.erase(conn_key);
  for (auto it = rx_routes_.begin(); it != rx_routes_.end();) {
    if (it->second == conn_key) {
      it = rx_routes_.erase(it);
    } else {
      ++it;
    }
  }
  EvictRxConn(conn_key);

  LOG(INFO) << "EpsChannel: unbound EPS connection {pid: " << bind.pid
            << ", fd: " << bind.fd << "}.";
  PostCtrlCompletion(req.id, true);
}

void EpsChannel::EvictRxConn(uint64_t conn_key) {
  const auto it = rx_conns_.find(conn_key);
  if (it == rx_conns_.end()) return;
  auto &conn = it->second;
  if (conn.ring != nullptr) user_ring_buffer__free(conn.ring);
  if (conn.map_fd >= 0) close(conn.map_fd);
  if (conn.wake_efd >= 0) close(conn.wake_efd);
  rx_conns_.erase(it);
}

void EpsChannel::Sweep() {
  // Evict cached rx_ring handles whose rx_rings entry the daemon removed or
  // replaced (inner map ID changed, e.g., after {pid, fd} reuse).
  std::vector<uint64_t> to_evict;
  for (const auto &conn_entry : rx_conns_) {
    EpsConnKey raw = UnpackConnKey(conn_entry.first);
    uint32_t inner_map_id = 0;
    if (bpf_map_lookup_elem(rx_rings_fd_, &raw, &inner_map_id) != 0 ||
        inner_map_id != conn_entry.second.inner_map_id)
      to_evict.push_back(conn_entry.first);
  }
  for (const auto key : to_evict) EvictRxConn(key);

  // Expire messages parked too long waiting for a BIND_CONN.
  for (auto it = pending_rx_.begin(); it != pending_rx_.end();) {
    if (++it->second.sweeps > kPendingRxMaxSweeps) {
      for (auto *head : it->second.msgs) FreeChain(head);
      DCHECK_GE(pending_rx_count_, it->second.msgs.size());
      pending_rx_count_ -= it->second.msgs.size();
      stats_.rx_pending_expired += it->second.msgs.size();
      // Allow a later message on this flow to re-post the NEW_FLOW event.
      new_flow_posted_.erase(it->first.Reversed());
      it = pending_rx_.erase(it);
    } else {
      // Still waiting for a BIND_CONN: re-post the NEW_FLOW event once per
      // sweep, in case the daemon missed it (e.g., a restart). BIND_CONN is
      // idempotent on the daemon->stack side, so duplicates are harmless.
      new_flow_posted_.erase(it->first.Reversed());
      PostNewFlowEvent(it->first.Reversed());
      ++it;
    }
  }
  stats_.rx_pending = pending_rx_count_;

  // Periodic fallback wake for parked senders (cheap when none are parked).
  WakeParkedSenders();

  TryFlushCtrlOut();

  LOG_EVERY_N(INFO, 60)
      << "EpsChannel " << GetName() << " stats: tx_converted="
      << stats_.tx_records_converted
      << " tx_held=" << stats_.tx_records_held_unbound
      << " tx_malformed=" << stats_.tx_records_malformed
      << " rx_delivered=" << stats_.rx_delivered
      << " rx_ring_full=" << stats_.rx_dropped_ring_full
      << " rx_oversize=" << stats_.rx_dropped_oversize
      << " rx_no_conn=" << stats_.rx_dropped_no_conn
      << " rx_pending=" << stats_.rx_pending
      << " rx_expired=" << stats_.rx_pending_expired;
}

uint32_t EpsChannel::DequeueCtrlRequests(MachnetCtrlQueueEntry_t *ctrl_entries,
                                         uint32_t nb_entries) {
  const uint32_t got =
      ShmChannel::DequeueCtrlRequests(ctrl_entries, nb_entries);

  uint32_t out = 0;
  for (uint32_t i = 0; i < got; i++) {
    switch (ctrl_entries[i].opcode) {
      case MACHNET_CTRL_OP_EPS_BIND_CONN:
        HandleBindConn(ctrl_entries[i]);
        break;
      case MACHNET_CTRL_OP_EPS_UNBIND_CONN:
        HandleUnbindConn(ctrl_entries[i]);
        break;
      default:
        // Not an EPS opcode: pass through to the engine.
        if (out != i) ctrl_entries[out] = ctrl_entries[i];
        out++;
        break;
    }
  }

  // The engine calls this on its slow tick; piggyback EPS maintenance.
  if (eps_ready_) Sweep();

  return out;
}

}  // namespace shm
}  // namespace juggler

#endif  // MACHNET_EPS_ENABLED

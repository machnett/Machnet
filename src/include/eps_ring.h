/**
 * @file eps_ring.h
 *
 * EPS eBPF datapath ABI definitions and the consumer-side BPF ringbuf
 * cursor used by `EpsChannel'. Kept free of Machnet/DPDK/libbpf includes so
 * it can be unit-tested standalone (see eps_ring_test.cc).
 *
 * The struct layouts must match the (hand-duplicated) definitions in the EPS
 * project's eps_hooks.bpf.c / poller.c / daemon.c.
 */
#ifndef SRC_INCLUDE_EPS_RING_H_
#define SRC_INCLUDE_EPS_RING_H_

#include <cstddef>
#include <cstdint>

namespace juggler {
namespace shm {

// Maximum payload of one EPS message record (both directions).
static constexpr uint32_t kEpsMaxPayload = 1500;

// EPS connection identity: {tgid, fd} of the application-side eventfd.
struct EpsConnKey {
  uint32_t pid;
  uint32_t fd;
};
static_assert(sizeof(EpsConnKey) == 8, "EpsConnKey ABI mismatch");

// One record in the EPS kernel tx_ring, as reserved by the eBPF sendto()
// hook. The BPF side always reserves the full sizeof(EpsTxEntry); `len'
// carries the actual payload length (<= kEpsMaxPayload).
struct EpsTxEntry {
  EpsConnKey conn_key;
  uint32_t len;
  uint8_t data[kEpsMaxPayload];
};
static_assert(sizeof(EpsTxEntry) == 1512, "EpsTxEntry ABI mismatch");

// Kernel BPF ringbuf record-header bits (see kernel/bpf/ringbuf.c and the
// EPS poller). Each record is [u32 len_flags][u32 pad][payload], and the
// data area is double-mmapped by the kernel so wrapping records are
// virtually contiguous.
static constexpr uint32_t kEpsRingbufBusyBit = 1u << 31;
static constexpr uint32_t kEpsRingbufDiscardBit = 1u << 30;
static constexpr uint32_t kEpsRingbufHdrSize = 8;

/**
 * @brief Consumer-side cursor over a kernel BPF ringbuf's mmap'ed pages.
 *
 * This is a faithful port of the EPS poller's raw tx_ring drain protocol:
 * acquire-load of the producer position and record header, release-store of
 * the consumer position, BUSY-bit spin-out and DISCARD-bit skip.
 *
 * Single consumer only. `Advance()' must be called exactly once per record
 * returned by `Peek()' (kRecord or kDiscard); not advancing "holds" the
 * record, and it is returned again on the next `Peek()'.
 */
class EpsTxRingReader {
 public:
  enum class Status {
    kEmpty,    // No committed records pending.
    kBusy,     // Next record reserved but not yet committed; retry later.
    kRecord,   // A record is available (payload/len are set).
    kDiscard,  // A discarded record; call Advance(len) to skip it.
  };

  EpsTxRingReader() = default;

  /**
   * @param consumer_pos Pointer to the consumer position word (shared with
   *                     the kernel; this reader writes it).
   * @param producer_pos Pointer to the producer position word (written by
   *                     the kernel).
   * @param data         Base of the (double-mapped) data area.
   * @param data_size    Size of the ring data area in bytes (power of two);
   *                     the accessible mapping must be 2 * data_size long.
   */
  void Init(volatile uint64_t *consumer_pos,
            const volatile uint64_t *producer_pos, const uint8_t *data,
            size_t data_size) {
    consumer_pos_ = consumer_pos;
    producer_pos_ = producer_pos;
    data_ = data;
    mask_ = data_size - 1;
    consumer_ = *consumer_pos_;
  }

  bool IsInitialized() const { return data_ != nullptr; }

  /**
   * @brief Peek at the next record without consuming it.
   * @param payload Out: pointer to the record payload (valid until Advance).
   * @param len     Out: record length in bytes (set for kRecord and
   *                kDiscard).
   */
  Status Peek(const uint8_t **payload, uint32_t *len) const {
    const uint64_t producer =
        __atomic_load_n(producer_pos_, __ATOMIC_ACQUIRE);
    if (producer == consumer_) return Status::kEmpty;

    const uint32_t *hdr = reinterpret_cast<const uint32_t *>(
        data_ + (consumer_ & mask_));
    const uint32_t len_flags = __atomic_load_n(hdr, __ATOMIC_ACQUIRE);
    if (len_flags & kEpsRingbufBusyBit) return Status::kBusy;

    *len = len_flags & ~(kEpsRingbufBusyBit | kEpsRingbufDiscardBit);
    if (len_flags & kEpsRingbufDiscardBit) return Status::kDiscard;

    *payload = reinterpret_cast<const uint8_t *>(hdr) + kEpsRingbufHdrSize;
    return Status::kRecord;
  }

  /**
   * @brief Consume the record last returned by Peek() and publish the new
   * consumer position to the kernel.
   * @param len The record length reported by Peek().
   */
  void Advance(uint32_t len) {
    consumer_ +=
        kEpsRingbufHdrSize + ((static_cast<uint64_t>(len) + 7) & ~7ULL);
    __atomic_store_n(consumer_pos_, consumer_, __ATOMIC_RELEASE);
  }

  uint64_t consumer_offset() const { return consumer_; }

 private:
  volatile uint64_t *consumer_pos_{nullptr};
  const volatile uint64_t *producer_pos_{nullptr};
  const uint8_t *data_{nullptr};
  uint64_t mask_{0};
  uint64_t consumer_{0};
};

}  // namespace shm
}  // namespace juggler

#endif  // SRC_INCLUDE_EPS_RING_H_

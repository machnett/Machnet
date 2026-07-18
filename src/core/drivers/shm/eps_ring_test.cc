/**
 * @file eps_ring_test.cc
 *
 * Unit tests for `EpsTxRingReader' — the consumer-side cursor over the EPS
 * kernel BPF ringbuf (tx_ring). The tests emulate the kernel's mmap layout
 * with plain memory: a data area of `kRingSize' bytes plus a mirror copy
 * right after it (the kernel double-maps the data pages so wrapping records
 * are virtually contiguous), and producer/consumer position words.
 */
#include <eps_ring.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

namespace {

using juggler::shm::EpsTxRingReader;
using juggler::shm::kEpsRingbufBusyBit;
using juggler::shm::kEpsRingbufDiscardBit;
using juggler::shm::kEpsRingbufHdrSize;
using Status = EpsTxRingReader::Status;

class FakeBpfRingbuf {
 public:
  static constexpr size_t kRingSize = 4096;

  FakeBpfRingbuf() : data_(2 * kRingSize, 0) {}

  // Reserve a record at the current producer position, filling the payload
  // and marking the header BUSY. Returns the header's logical offset.
  uint64_t Reserve(const std::vector<uint8_t> &payload) {
    const uint64_t hdr_off = producer_;
    WriteU32(hdr_off, static_cast<uint32_t>(payload.size()) |
                          kEpsRingbufBusyBit);
    WriteU32(hdr_off + 4, 0);  // padding
    for (size_t i = 0; i < payload.size(); i++) {
      WriteU8(hdr_off + kEpsRingbufHdrSize + i, payload[i]);
    }
    producer_ += kEpsRingbufHdrSize + ((payload.size() + 7) & ~7ULL);
    return hdr_off;
  }

  // Commit (clear BUSY) and publish the producer position.
  void Commit(uint64_t hdr_off, uint32_t len, bool discard = false) {
    uint32_t len_flags = len;
    if (discard) len_flags |= kEpsRingbufDiscardBit;
    WriteU32(hdr_off, len_flags);
    __atomic_store_n(&producer_pos_, producer_, __ATOMIC_RELEASE);
  }

  // One-call produce: reserve + commit.
  void Produce(const std::vector<uint8_t> &payload, bool discard = false) {
    const auto hdr = Reserve(payload);
    Commit(hdr, static_cast<uint32_t>(payload.size()), discard);
  }

  volatile uint64_t *consumer_pos() { return &consumer_pos_; }
  const volatile uint64_t *producer_pos() const { return &producer_pos_; }
  const uint8_t *data() const { return data_.data(); }
  uint64_t consumer_pos_value() const { return consumer_pos_; }

 private:
  // All writes go through the primary region and are mirrored into the
  // second half, emulating the kernel's double mapping.
  void WriteU8(uint64_t logical_off, uint8_t value) {
    const size_t off = logical_off & (kRingSize - 1);
    data_[off] = value;
    data_[off + kRingSize] = value;
  }
  void WriteU32(uint64_t logical_off, uint32_t value) {
    for (int i = 0; i < 4; i++) {
      WriteU8(logical_off + i, static_cast<uint8_t>(value >> (8 * i)));
    }
  }

  std::vector<uint8_t> data_;
  uint64_t producer_{0};  // Producer's private cursor.
  uint64_t producer_pos_{0};
  uint64_t consumer_pos_{0};
};

std::vector<uint8_t> Pattern(size_t len, uint8_t seed) {
  std::vector<uint8_t> v(len);
  for (size_t i = 0; i < len; i++) v[i] = static_cast<uint8_t>(seed + i);
  return v;
}

EpsTxRingReader MakeReader(FakeBpfRingbuf *ring) {
  EpsTxRingReader reader;
  reader.Init(ring->consumer_pos(), ring->producer_pos(), ring->data(),
              FakeBpfRingbuf::kRingSize);
  return reader;
}

TEST(EpsTxRingReader, EmptyRing) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  EXPECT_EQ(reader.Peek(&payload, &len), Status::kEmpty);
}

TEST(EpsTxRingReader, SingleRecordRoundtrip) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  const auto data = Pattern(100, 7);
  ring.Produce(data);

  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  ASSERT_EQ(reader.Peek(&payload, &len), Status::kRecord);
  ASSERT_EQ(len, 100u);
  EXPECT_EQ(memcmp(payload, data.data(), data.size()), 0);

  reader.Advance(len);
  // Record stride is 8-byte header + payload rounded up to 8.
  EXPECT_EQ(ring.consumer_pos_value(), kEpsRingbufHdrSize + 104u);
  EXPECT_EQ(reader.Peek(&payload, &len), Status::kEmpty);
}

TEST(EpsTxRingReader, BusyRecordSpinsOut) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  const auto data = Pattern(32, 1);
  const auto hdr = ring.Reserve(data);
  // Publish producer_pos while the record header still has the BUSY bit,
  // emulating the kernel's reserved-but-not-yet-committed window.
  ring.Commit(hdr, 32u | kEpsRingbufBusyBit);

  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  EXPECT_EQ(reader.Peek(&payload, &len), Status::kBusy);

  // Consumer position must not move while busy.
  EXPECT_EQ(ring.consumer_pos_value(), 0u);

  // Once committed for real, the record becomes visible.
  ring.Commit(hdr, 32u);
  ASSERT_EQ(reader.Peek(&payload, &len), Status::kRecord);
  ASSERT_EQ(len, 32u);
  EXPECT_EQ(memcmp(payload, data.data(), data.size()), 0);
}

TEST(EpsTxRingReader, DiscardRecordIsSkippable) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  ring.Produce(Pattern(48, 9), /*discard=*/true);
  const auto data = Pattern(24, 5);
  ring.Produce(data);

  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  ASSERT_EQ(reader.Peek(&payload, &len), Status::kDiscard);
  EXPECT_EQ(len, 48u);
  reader.Advance(len);

  ASSERT_EQ(reader.Peek(&payload, &len), Status::kRecord);
  ASSERT_EQ(len, 24u);
  EXPECT_EQ(memcmp(payload, data.data(), data.size()), 0);
}

TEST(EpsTxRingReader, PeekWithoutAdvanceHoldsTheRecord) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  const auto data = Pattern(80, 11);
  ring.Produce(data);

  const uint8_t *payload1 = nullptr;
  uint32_t len1 = 0;
  ASSERT_EQ(reader.Peek(&payload1, &len1), Status::kRecord);

  // A second Peek without Advance returns the same record (hold-slot
  // backpressure), and the shared consumer position is untouched.
  const uint8_t *payload2 = nullptr;
  uint32_t len2 = 0;
  ASSERT_EQ(reader.Peek(&payload2, &len2), Status::kRecord);
  EXPECT_EQ(payload1, payload2);
  EXPECT_EQ(len1, len2);
  EXPECT_EQ(ring.consumer_pos_value(), 0u);
}

TEST(EpsTxRingReader, DrainsMultipleRecords) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  constexpr int kRecords = 16;
  for (int i = 0; i < kRecords; i++) {
    ring.Produce(Pattern(60 + i, static_cast<uint8_t>(i)));
  }

  for (int i = 0; i < kRecords; i++) {
    const uint8_t *payload = nullptr;
    uint32_t len = 0;
    ASSERT_EQ(reader.Peek(&payload, &len), Status::kRecord) << "record " << i;
    ASSERT_EQ(len, static_cast<uint32_t>(60 + i));
    const auto expected = Pattern(60 + i, static_cast<uint8_t>(i));
    EXPECT_EQ(memcmp(payload, expected.data(), expected.size()), 0);
    reader.Advance(len);
  }

  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  EXPECT_EQ(reader.Peek(&payload, &len), Status::kEmpty);
}

TEST(EpsTxRingReader, WrappingRecordReadsContiguously) {
  FakeBpfRingbuf ring;
  auto reader = MakeReader(&ring);

  // Seven 512-byte records (stride 520) put the producer at offset 3640; the
  // next 512-byte record then spans [3640, 4160), crossing the 4096-byte
  // wrap boundary.
  const size_t kFillerPayload = 512;
  const size_t kStride =
      kEpsRingbufHdrSize + ((kFillerPayload + 7) & ~7ULL);  // 520
  for (int i = 0; i < 7; i++) ring.Produce(Pattern(kFillerPayload, 0xAA));

  // Drain the fillers so the wrapped region is free for the producer.
  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  for (int i = 0; i < 7; i++) {
    ASSERT_EQ(reader.Peek(&payload, &len), Status::kRecord);
    reader.Advance(len);
  }
  ASSERT_EQ(ring.consumer_pos_value(), 7 * kStride);
  ASSERT_GT(7 * kStride + kEpsRingbufHdrSize + kFillerPayload,
            FakeBpfRingbuf::kRingSize);  // The next record really wraps.

  const auto data = Pattern(512, 0x5C);
  ring.Produce(data);

  ASSERT_EQ(reader.Peek(&payload, &len), Status::kRecord);
  ASSERT_EQ(len, 512u);
  EXPECT_EQ(memcmp(payload, data.data(), data.size()), 0);
  reader.Advance(len);
  EXPECT_EQ(reader.Peek(&payload, &len), Status::kEmpty);
}

TEST(EpsTxRingReader, SeedsFromExistingConsumerPosition) {
  FakeBpfRingbuf ring;

  // Produce two records and consume one with a first reader.
  const auto first = Pattern(40, 1);
  const auto second = Pattern(56, 2);
  ring.Produce(first);
  ring.Produce(second);

  auto reader1 = MakeReader(&ring);
  const uint8_t *payload = nullptr;
  uint32_t len = 0;
  ASSERT_EQ(reader1.Peek(&payload, &len), Status::kRecord);
  reader1.Advance(len);

  // A new reader (e.g., after a Machnet restart) must resume from the
  // published consumer position, not from zero.
  auto reader2 = MakeReader(&ring);
  ASSERT_EQ(reader2.Peek(&payload, &len), Status::kRecord);
  ASSERT_EQ(len, 56u);
  EXPECT_EQ(memcmp(payload, second.data(), second.size()), 0);
}

}  // namespace

int main(int argc, char **argv) {
  ::google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}

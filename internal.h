#pragma once

#include <atomic>
#include <cstdint>

namespace blackbox {
namespace internal {

static constexpr auto BLACKBOX_SHM_FMTSTR = "/blackbox-{}";

// Header at beginning of shared memory segment
struct Blackbox {
  // Sequence number of blackbox.
  // Odd value means write is in progress.
  std::atomic_uint64_t sequence;
  // Offset of `head` in ring buffer
  std::uint64_t head;
  // Logical size of blackbox.
  // `(head + size) % psize` is tail index.
  std::uint64_t size;
  // Physical (ie. allocated) size of ring buffer
  std::uint64_t psize;
  // Bytes of padding until start of ring buffer.
  // This is necessary to achieve PAGE_SIZE alignment so
  // we can double map the ring buffer.
  std::uint64_t padding;
  // Start of padding.
  // `->padding_start + padding` is start of ring buffer.
  std::uint8_t padding_start[];
};
static_assert(sizeof(std::atomic_uint64_t) == sizeof(std::uint64_t));
static_assert(std::atomic_uint64_t::is_always_lock_free);
static_assert(sizeof(Blackbox) == offsetof(Blackbox, padding_start));

enum class Type : std::uint8_t {
  Invalid = 0,
  String,
  Int,
  KeyValue,
};
static_assert(sizeof(Type) == 1);

// Type header for each entry in the blackbox.
//
// This is the outer-most header.
struct Header {
  // Type of entry
  Type type;
  // Length of type dependent data
  std::uint64_t len;
  // Start of type dependent data
  std::uint8_t data[];

  // Returns number of bytes this entry occupies (including header)
  std::uint64_t size() { return sizeof(Header) + len; }
} __attribute__((packed));
static_assert(sizeof(Header) == offsetof(Header, data));

// String entry.
//
// NUL terminator is not stored.
struct StringEntry {
  // Bytes in string
  uint64_t len;
  // Start of string
  char string[];

  // Returns number of bytes this entry occupies (including header)
  std::uint64_t size() { return sizeof(StringEntry) + len; }
};
static_assert(sizeof(StringEntry) == sizeof(uint64_t));
static_assert(sizeof(StringEntry) == offsetof(StringEntry, string));

// Signed integer entry.
struct IntEntry {
  int64_t val;

  // Returns number of bytes this entry occupies (including header)
  std::uint64_t size() { return sizeof(IntEntry); }
};

// Key/value entry.
//
// No NUL terminators are stored.
struct KeyValueEntry {
  // Bytes in key string
  uint64_t key_len;
  // Bytes in value string
  uint64_t val_len;
  // Beginning of key/value data.
  // Key/value are stored tip to tail.
  char data[];

  // Returns number of bytes this entry occupies (including header)
  std::uint64_t size() { return sizeof(KeyValueEntry) + key_len + val_len; }
};

Header *header(Blackbox *blackbox, std::uint64_t off) {
  auto data = blackbox->padding_start + blackbox->padding;
  return reinterpret_cast<Header *>(data + off);
}

Header *head(Blackbox *blackbox) { return header(blackbox, blackbox->head); }

Header *tail(Blackbox *blackbox) {
  auto off = (blackbox->head + blackbox->size) % blackbox->psize;
  return header(blackbox, off);
}

template <typename T> T *entry(Header *e) {
  return reinterpret_cast<T *>(e->data);
}

} // namespace internal
} // namespace blackbox

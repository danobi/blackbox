#pragma once

#include <atomic>
#include <cstdint>

namespace blackbox {
namespace internal {

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

// Type header for each entry in the blackbox.
//
// This is the outer-most header.
struct Header {
  // Type of entry
  Type type;
  // Start of type dependent data
  std::uint8_t data[];

  std::uint64_t size() {
    auto sz = sizeof(Header);

    switch (type) {
    case Type::Invalid:
      // Very suspicious to take size of invalid entry.
      // But technically it has no trailing value.
      break;
    case Type::String:
      sz += reinterpret_cast<StringEntry *>(data)->size();
      break;
    case Type::Int:
      sz += reinterpret_cast<IntEntry *>(data)->size();
      break;
    case Type::KeyValue:
      sz += reinterpret_cast<KeyValueEntry *>(data)->size();
      break;
    }

    return sz;
  }
};
static_assert(sizeof(Header) == sizeof(Type));
static_assert(sizeof(Header) == offsetof(Header, data));

} // namespace internal
} // namespace blackbox

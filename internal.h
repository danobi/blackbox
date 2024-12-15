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
  // Offset of `head` in `data`.
  std::uint64_t head;
  // Logical size of blackbox.
  // `(head + size) % psize` is tail index.
  std::uint64_t size;
  // Physical (ie. allocated) size of `data`
  std::uint64_t psize;
  // Ring buffer
  std::uint8_t data[];
};
static_assert(sizeof(std::atomic_uint64_t) == sizeof(std::uint64_t));
static_assert(std::atomic_uint64_t::is_always_lock_free);
static_assert(sizeof(Blackbox) == offsetof(Blackbox, data));

enum class Type : std::uint8_t {
  Invalid = 0,
  String,
  Int,
  KeyValue,
};
static_assert(sizeof(Type) == 1);

// Header for each entry in the blackbox
struct Header {
  // Type of entry
  Type type;
  // Start of type dependent data
  std::uint8_t data[];
};
static_assert(sizeof(Header) == sizeof(Type));
static_assert(sizeof(Header) == offsetof(Header, data));

// String entry.
// NUL terminator is not stored.
struct StringEntry {
  // Bytes in string
  uint64_t len;
  // Start of string
  std::uint8_t string[];

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
// No NUL terminators are stored.
struct KeyValueEntry {
  // Bytes in key string
  uint64_t key_len;
  // Bytes in value string
  uint64_t val_len;
  // Beginning of key/value data.
  // Key/value are stored tip to tail.
  std::uint8_t data[];

  // Returns number of bytes this entry occupies (including header)
  std::uint64_t size() { return sizeof(KeyValueEntry) + key_len + val_len; }
};

} // namespace internal
} // namespace blackbox

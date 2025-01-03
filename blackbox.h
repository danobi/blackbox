#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string_view>

// Blackbox acts as a "flight recorder" for your application. It acts as a
// singleton that holds structured data with FIFO overwrite semantics.
//
// The blackbox is only written to from inside the application. However, it is
// designed to be extractable from:
//
//    1. Inside the application
//    2. Outside the application (while alive)
//    3. Outside the application (after a crash)
//
// The blackbox is designed with data consistency in mind. It is always
// possible to extract a consistent snapshot while the process is alive
// (assuming a reasonable amount of writes). In the event the application
// crashes, the extractor will be able to detect any inconsistency.

namespace blackbox {

// Default size of the ring buffer backing the blackbox.
//
// This does not include the page blackbox reserves for management overhead.
constexpr std::size_t DEFAULT_SIZE = 512 << 10;

// Thread-safe initialization routine for blackbox.
//
// Must be called before any other calls to blackbox APIs. Otherwise calling
// any of the APIs is undefined behavior.
//
// `size` must be a multiple of PAGE_SIZE. If `size` is not, blackbox will
// round up to the nearest multiple of PAGE_SIZE.
//
// On success, returns 0. On failure, returns negative error code suitable
// for std::sterror(-ret);
int init(std::size_t size = DEFAULT_SIZE) noexcept;

// Thread-safe writes into the blackbox.
//
// On success, returns the number of entries that were overwritten to make
// space for the new entry.
//
// On failure, returns negative error code. The returned value is suitable
// for std::strerror(-ret).
//
// These are safe to call inside signal handlers.
int write(std::string_view s) noexcept;
int write(std::int64_t i) noexcept;
int write(std::string_view key, std::string_view value) noexcept;

// Dump contents of blackbox to an output stream with each entry on
// its own line.
//
// Returns number of entries dumped on success. On failure, returns
// negative error code suitable for std::strerror(-ret).
//
// This is safe to call inside signal handlers, assuming `operator<<`,
// is async signal safe.
int dump(std::ostream &out);

} // namespace blackbox

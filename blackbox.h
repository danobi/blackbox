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
// possible to extract consistent a consistent snapshot while the process is
// alive (assuming a reasonable amount of writes). In the event the application
// crashes, the extractor will be able to detect any inconsistency.

namespace blackbox {

// Optional thread-safe initialization routine for blackbox.
//
// If not called, the first write() will initialize blackbox to default
// size and abort on allocation failure. If called explicitly, init()
// will throw on failure.
//
// `size` may be set to zero to indicate default size.
void init(std::size_t size);

// Thread-safe writes into the blackbox.
//
// On success, returns the number of entries that were overwritten to make
// space for the new entry.
//
// On failure, returns negative error code. The returned value is suitable
// for std::strerror(-ret).
int write(std::string_view s) noexcept;
int write(std::int64_t i) noexcept;
int write(std::string_view key, std::string_view value) noexcept;

// Dump contents of blackbox to an output stream with each entry on
// its own line.
//
// Returns number of entries dumped on success. On failure, returns
// negative error code suitable for std::strerror(-ret).
int dump(std::ostream &out);

} // namespace blackbox

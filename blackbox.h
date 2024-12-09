#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

// Blackbox acts as a "flight recorder" for you application. It's a global
// singleton ring buffer for structured data that callers can insert.
//
// The blackbox is designed to be both extractable from outside the application
// while the process is alive or from a post-mortem coredump. Blackbox provides
// data consistency guarantees.
namespace blackbox {

// Optional initialization routine for blackbox.
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

} // namespace blackbox

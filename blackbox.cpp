#include "blackbox.h"

#include <atomic>
#include <cerrno>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>

namespace blackbox {
namespace {

// Default size is 512 KB
static constexpr std::size_t DEFAULT_SIZE = 512 << 10;

// Protects all operations to blackbox
std::mutex lock;

// Internal state
std::size_t allocated_size = 0;
std::unique_ptr<unsigned char[]> buf;

void begin_write() {
  // TODO: increment generation with proper barrier
}

void end_write() {
  // TODO: increment generation with proper barrier
}

void init_locked(std::size_t size) {
  begin_write();
  size = size ? size : DEFAULT_SIZE;
  buf = std::make_unique<unsigned char[]>(size);
  allocated_size = size;
  end_write();
}

void default_init() {
  try {
    init(0);
  } catch (const std::exception &ex) {
    std::cerr << "blackbox: fatal failure to allocate" << std::endl;
    std::abort();
  }
}

} // namespace

// External state
extern "C" {
std::uint64_t __blackbox_generation = 0;
unsigned char *__blackbox_head = nullptr;
std::uint64_t __blackbox_size = 0;
}

void init(std::size_t size) {
  std::lock_guard<decltype(lock)> guard(lock);
  if (!buf) {
    init_locked(size);
  }
}

int write(std::string_view s) noexcept {
  default_init();

  // TODO: implement
  (void)s;
  return -ENOSYS;
}

int write(std::int64_t i) noexcept {
  default_init();

  // TODO: implement
  (void)i;
  return -ENOSYS;
}

int write(std::string_view key, std::string_view value) noexcept {
  default_init();

  // TODO: implement
  (void)key;
  (void)value;
  return -ENOSYS;
}

} // namespace blackbox

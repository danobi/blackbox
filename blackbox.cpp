#include "blackbox.h"

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <exception>
#include <format>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <system_error>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"

namespace blackbox {
namespace {

// Default size is 512 KB
constexpr std::size_t DEFAULT_SIZE = 512 << 10;

// Protects all operations to blackbox
std::mutex lock;

// Internal state
std::once_flag init_flag;
internal::Header *header = nullptr;

void default_init() {
  try {
    init(0);
  } catch (const std::exception &ex) {
    std::cerr << "blackbox: fatal failure to allocate" << std::endl;
    std::abort();
  }
}

void write_locked(std::function<void()> f) {
  // Provides its own synchronization
  default_init();

  // Ensure only one writer is writing
  lock.lock();

  // Transition into write and prevent any previous stores from being
  // reordered after this increment.
  header->sequence.fetch_add(1, std::memory_order_release);

  // Fence writes such that subsequent writes are not ordered before
  // prior sequence increment. The previous std::memory_order_release only
  // ensures prior writes are not ordered after the atomic operation.
  std::atomic_thread_fence(std::memory_order_release);

  // Write new entry
  f();

  // Transition out of write and prevent any previous stores from being
  // reordered after this increment.
  //
  // Note we do not do additional fencing like above b/c we do not care
  // at this point if subsequent writes are ordered before the transition.
  header->sequence.fetch_add(1, std::memory_order_release);

  // Pair with above lock()
  lock.unlock();
}

std::string get_shm_name() {
  auto pid = ::getpid();
  return std::format("/blackbox-{}", pid);
}

void cleanup() {
  // We actually want to recalculate this in case we were forked off from
  // the parent and exec() has not been called to clear the atexit() handlers yet.
  auto shm_name = get_shm_name();
  ::shm_unlink(shm_name.c_str());
}

// Makes room in ring buffer for at least `bytes` bytes.
// Returns number of evicted entries.
int make_room_for(std::uint64_t bytes) {
  if (bytes > header->physical_size) {
    return -ENOSPC;
  }

  // XXX: implement
  return -ENOSYS;
}

// Inserts an entry into the ring buffer.
// Returns number of entries that had to be evicted.
template<typename T>
int insert(T *entry) {
  auto sz = sizeof(internal::Entry) + entry->size();
  auto evicted = make_room_for(sz);
  if (evicted < 0) {
    return evicted;
  }

  // XXX: implement
  return -ENOSYS;
}

} // namespace

void init(std::size_t size) {
  std::call_once(init_flag, [size]() {
      // Create shared memory segment
      auto shm_name = get_shm_name();
      auto fd = ::shm_open(shm_name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
      if (fd < 1) {
        throw std::system_error(errno, std::system_category(), "shm_open");
      }

      // Setup destructor for normal program termination.
      //
      // In other words, we want the shared memory segment to persist if SIGKILL
      // was delivered.
      if (std::atexit(cleanup)) {
        throw std::system_error(errno, std::generic_category(), "atexit");
      }

      // Size segment to requested size
      auto physical_size = sizeof(internal::Header);
      auto ring_size = size ? size : DEFAULT_SIZE;
      physical_size += ring_size;
      if (::ftruncate(fd, physical_size) < 0) {
        throw std::system_error(errno, std::system_category(), "ftruncate");
      }

      // Map it into our address space
      header = static_cast<internal::Header *>(::mmap(
            nullptr, physical_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
      if (header == MAP_FAILED) {
        throw std::system_error(errno, std::system_category(), "mmap");
      }

      // Initialize the blackbox
      write_locked([size, ring_size]() {
          header->head = 0;
          header->size = 0;
          header->physical_size = ring_size;
          std::memset(header->data, 0, ring_size);
      });
  });
}

int write(std::string_view s) noexcept {
  auto sz = sizeof(internal::StringEntry) + s.size();
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<internal::StringEntry *>(buffer.data());
  entry->len = s.size();
  std::memcpy(entry->string, s.data(), s.size());

  return insert(entry);
}

int write(std::int64_t i) noexcept {
  auto sz = sizeof(internal::IntEntry);
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<internal::IntEntry *>(buffer.data());
  entry->val = i;

  return insert(entry);
}

int write(std::string_view key, std::string_view value) noexcept {
  auto sz = sizeof(internal::KeyValueEntry) + key.size() + value.size();
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<internal::KeyValueEntry *>(buffer.data());
  entry->key_len = key.size();
  entry->val_len = value.size();
  std::memcpy(entry->data, key.data(), key.size());
  std::memcpy(entry->data + key.size(), value.data(), value.size());

  return insert(entry);
}

} // namespace blackbox

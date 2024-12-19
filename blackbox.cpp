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

using namespace internal;

// Protects all operations to blackbox
std::mutex lock;

// Internal state
std::once_flag init_flag;
Blackbox *blackbox = nullptr;

std::size_t round_up_to_nearest(std::size_t size, std::size_t align) {
  return (size + align - 1) & ~(align - 1);
}

template <typename F> auto write_locked(F &&f) -> decltype(f()) {
  // Ensure only one writer is writing
  lock.lock();

  // Transition into write and prevent any stores from being reordered around
  // this increment.
  //
  // memory_order_acq_rel is chosen b/c the critial section (subsequent stores)
  // must not be reordered before the sequence is incremented.
  // memory_order_release is not sufficient as it only guarantees prior stores
  // are not reordered after the increment, and not the other way around (which
  // we need).
  blackbox->sequence.fetch_add(1, std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acq_rel);

  // Write new entry
  auto retval = f();

  // Transition out of write and prevent any previous stores from being
  // reordered after this increment.
  //
  // Note we do not need acquire_release semantics like above b/c release
  // semantics are strong enough to ensure stores in the critical section will
  // be visible before the sequence increment.
  //
  // Any subsequent stores are free to move into the critical section if it
  // makes the program run faster. Any subsequent critical sections will be
  // fenced by its corresponding acquire_release increment.
  blackbox->sequence.fetch_add(1, std::memory_order_release);

  // Pair with above lock()
  lock.unlock();

  return retval;
}

std::string get_shm_name() {
  auto pid = ::getpid();
  return std::format(BLACKBOX_SHM_FMTSTR, pid);
}

void cleanup() {
  // We actually want to recalculate this in case we were forked off from
  // the parent and exec() has not been called to clear the atexit() handlers
  // yet.
  auto shm_name = get_shm_name();
  ::shm_unlink(shm_name.c_str());
}

int init_once(std::size_t size) noexcept {
  std::size_t addr_space_size;
  std::size_t page_size;
  std::size_t ring_size;
  char *ptr;
  int err;

  // Create shared memory segment
  auto shm_name = get_shm_name();
  auto fd = ::shm_open(shm_name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fd < 0) {
    return -errno;
  }

  // Setup destructor for normal program termination.
  //
  // In other words, we want the shared memory segment to persist if SIGKILL
  // was delivered.
  if (std::atexit(cleanup)) {
    err = -errno;
    goto cleanup_shm;
  }

  // Give ring buffer PAGE_SIZE alignment so we can double map
  page_size = getpagesize();
  ring_size = round_up_to_nearest(size, page_size);

  // Size segment to requested size.
  // NB: we give the header a full page to achieve alignment.
  if (::ftruncate(fd, page_size + ring_size) < 0) {
    err = -errno;
    goto cleanup_shm;
  }

  // Reserve header + 2x ringbuffer address space to prevent races with
  // any other allocations the application might be doing.
  //
  // We're going to mmap the ring buffer twice so access is always linear
  // in our address space. This prevents TLV headers from being split
  // and thus allows reliable pointer casts.
  addr_space_size = page_size + 2 * ring_size;
  ptr = static_cast<char *>(::mmap(nullptr, addr_space_size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (ptr == MAP_FAILED) {
    err = -errno;
    goto cleanup_shm;
  }

  // Map blackbox header
  if (::mmap(ptr, page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
             0) == MAP_FAILED) {
    err = -errno;
    goto cleanup;
  }

  // Map first copy of ring buffer
  if (::mmap(ptr + page_size, ring_size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, fd, page_size) == MAP_FAILED) {
    err = -errno;
    goto cleanup;
  }

  // Map second copy of ring buffer at tail of first copy
  if (::mmap(ptr + page_size + ring_size, ring_size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, fd, page_size) == MAP_FAILED) {
    err = -errno;
    goto cleanup;
  }

  // Done with fd now
  ::close(fd);

  // Initialize the blackbox
  blackbox = reinterpret_cast<Blackbox *>(ptr);
  blackbox->head = 0;
  blackbox->size = 0;
  blackbox->psize = ring_size;
  blackbox->padding = page_size - sizeof(Blackbox);
  std::memset(blackbox->padding_start + blackbox->padding, 0, ring_size);
  return 0;

cleanup:
  ::munmap(ptr, addr_space_size);
cleanup_shm:
  ::close(fd);
  ::shm_unlink(shm_name.c_str());
  return err;
}

// Makes room in ring buffer for at least `bytes` bytes.
//
// Returns number of evicted entries.
int make_room_for(std::uint64_t bytes) {
  // Entry is too big to ever insert
  if (bytes > blackbox->psize) {
    return -E2BIG;
  }

  // There's already enough free space
  if (bytes <= (blackbox->psize - blackbox->size)) {
    return 0;
  }

  // Delete stuff from head until there's enough room
  int evicted = 0;
  while ((blackbox->psize - blackbox->size) < bytes) {
    auto hdr = head(blackbox);
    assert(hdr->type != Type::Invalid);

    auto deleted_sz = hdr->size();
    blackbox->size -= deleted_sz;
    blackbox->head = (blackbox->head + deleted_sz) % blackbox->psize;
    evicted++;
  }

  return evicted;
}

// Inserts an entry into the ring buffer.
//
// Returns number of entries that had to be evicted.
int insert(Type type, void *entry, std::uint64_t entry_size) {
  return write_locked([&]() {
    auto size = sizeof(Header) + entry_size;
    auto evicted = make_room_for(size);
    if (evicted < 0) {
      return evicted;
    }

    auto hdr = tail(blackbox);
    hdr->type = type;
    hdr->len = entry_size;
    std::memcpy(hdr->data, entry, entry_size);
    blackbox->size += size;

    return evicted;
  });
}

} // namespace

int init(std::size_t size) noexcept {
  static int ret;
  std::call_once(init_flag, [&]() { ret = init_once(size); });
  return ret;
}

int write(std::string_view s) noexcept {
  auto sz = sizeof(StringEntry) + s.size();
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<StringEntry *>(buffer.data());
  entry->len = s.size();
  std::memcpy(entry->string, s.data(), s.size());
  assert(sz == entry->size());

  return insert(Type::String, entry, entry->size());
}

int write(std::int64_t i) noexcept {
  auto sz = sizeof(IntEntry);
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<IntEntry *>(buffer.data());
  entry->val = i;
  assert(sz == entry->size());

  return insert(Type::Int, entry, entry->size());
}

int write(std::string_view key, std::string_view value) noexcept {
  auto sz = sizeof(KeyValueEntry) + key.size() + value.size();
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<KeyValueEntry *>(buffer.data());
  entry->key_len = key.size();
  entry->val_len = value.size();
  std::memcpy(entry->data, key.data(), key.size());
  std::memcpy(entry->data + key.size(), value.data(), value.size());
  assert(sz == entry->size());

  return insert(Type::KeyValue, entry, entry->size());
}

int dump(std::ostream &out) {
  std::scoped_lock guard(lock);

  int dumped = 0;
  auto head = blackbox->head;
  auto tail = blackbox->head + blackbox->size;
  while (head != tail) {
    auto hdr = header(blackbox, head);

    switch (hdr->type) {
    case Type::String: {
      auto str = entry<StringEntry>(hdr);
      out << std::string_view(str->string, str->len) << std::endl;
      break;
    }
    case Type::Int: {
      auto i = entry<IntEntry>(hdr);
      out << i->val << std::endl;
      break;
    }
    case Type::KeyValue: {
      auto kv = entry<KeyValueEntry>(hdr);
      auto key = std::string_view(kv->data, kv->key_len);
      auto val = std::string_view(kv->data + kv->key_len, kv->val_len);
      out << std::format("{}={}", key, val) << std::endl;
      break;
    }
    case Type::Invalid:
      return -EINVAL;
    }

    dumped++;
    head += hdr->size();
  }

  return dumped;
}

} // namespace blackbox

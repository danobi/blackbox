#include "blackbox.h"

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <exception>
#include <concepts>
#include <optional>
#include <format>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>

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
thread_local sig_atomic_t lock_taken;

std::size_t round_up_to_nearest(std::size_t size, std::size_t align) {
  return (size + align - 1) & ~(align - 1);
}

// Utility class for signal-safe RAII locking
class SignalSafeLock {
 public:
  static std::optional<SignalSafeLock> grabLock() {
    if (lock_taken) {
      return std::nullopt;
    }
    return SignalSafeLock();
  }

  // Locks are non-copyable
  SignalSafeLock(const SignalSafeLock &) = delete;
  SignalSafeLock &operator=(const SignalSafeLock &) = delete;

  SignalSafeLock(SignalSafeLock &&other) = default;

  ~SignalSafeLock() {
    // Do nothing if we are in moved-from state
    if (lock_.owns_lock()) {
      lock_.unlock();
      lock_taken = 0;
    }
  }

 private:
  SignalSafeLock() : lock_(lock, std::defer_lock) {
    lock_taken = 1;
    lock_.lock();
  }

  std::unique_lock<std::mutex> lock_;
};

template <typename F> int write_locked(F &&f)
  requires std::signed_integral<decltype(f())>
{
  // Ensure only one writer is writing
  auto guard = SignalSafeLock::grabLock();
  if (!guard) {
    return -EDEADLK;
  }

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

// Utility class just to make cleanup simpler
class InitCleaner {
public:
  InitCleaner() = default;
  ~InitCleaner() {
    if (disarm_) {
      return;
    }
    if (addr_space) {
      ::munmap(addr_space, addr_space_size);
    }
    if (shm_fd >= 0) {
      ::close(shm_fd);
    }
    if (shm_name) {
      ::shm_unlink(shm_name);
    }
  }

  void disarm() { disarm_ = true; }

  int shm_fd = -1;
  char *addr_space = nullptr;
  std::size_t addr_space_size = 0;
  const char *shm_name = nullptr;

private:
  bool disarm_ = false;
};

int init_once(std::size_t size) noexcept {
  InitCleaner cleaner;

  // Create shared memory segment
  auto shm_name = get_shm_name();
  auto fd = ::shm_open(shm_name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fd < 0) {
    return -errno;
  } else {
    cleaner.shm_fd = fd;
  }

  // Setup destructor for normal program termination.
  //
  // In other words, we want the shared memory segment to persist if SIGKILL
  // was delivered.
  if (std::atexit(cleanup)) {
    return -errno;
  }

  // Give ring buffer PAGE_SIZE alignment so we can double map
  auto page_size = getpagesize();
  auto ring_size = round_up_to_nearest(size, page_size);

  // Size segment to requested size.
  // NB: we give the header a full page to achieve alignment.
  if (::ftruncate(fd, page_size + ring_size) < 0) {
    return -errno;
  }

  // Reserve header + 2x ringbuffer address space to prevent races with
  // any other allocations the application might be doing.
  //
  // We're going to mmap the ring buffer twice so access is always linear
  // in our address space. This prevents TLV headers from being split
  // and thus allows reliable pointer casts.
  auto addr_space_size = page_size + 2 * ring_size;
  auto ptr = static_cast<char *>(::mmap(nullptr, addr_space_size,
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (ptr == MAP_FAILED) {
    return -errno;
  } else {
    cleaner.addr_space = ptr;
    cleaner.addr_space_size = addr_space_size;
  }

  // Map blackbox header
  if (::mmap(ptr, page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
             0) == MAP_FAILED) {
    return -errno;
  }

  // Map first copy of ring buffer
  if (::mmap(ptr + page_size, ring_size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, fd, page_size) == MAP_FAILED) {
    return -errno;
  }

  // Map second copy of ring buffer at tail of first copy
  if (::mmap(ptr + page_size + ring_size, ring_size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, fd, page_size) == MAP_FAILED) {
    return -errno;
  }

  // Initialize the blackbox
  blackbox = reinterpret_cast<Blackbox *>(ptr);
  blackbox->head = 0;
  blackbox->size = 0;
  blackbox->psize = ring_size;
  blackbox->padding = page_size - sizeof(Blackbox);
  std::memset(blackbox->padding_start + blackbox->padding, 0, ring_size);

  // We succeeded in initialization, so disarm cleanup
  cleaner.disarm();
  // We're done with shared memory handle, though
  ::close(fd);

  return 0;
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
  // Attempt to acquire lock. We cannot blindly block - we could be
  // running in signal handler context (eg SIGSEGV handling) and have
  // interrupted an in-progress write. Therefore return an error if
  // lock is already taken.
  auto guard = SignalSafeLock::grabLock();
  if (!guard) {
    return -EDEADLK;
  }

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
      out << key << "=" << val << std::endl;
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

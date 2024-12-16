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

// Default size is 512 KB
constexpr std::size_t DEFAULT_SIZE = 512 << 10;

// Protects all operations to blackbox
std::mutex lock;

// Internal state
std::once_flag init_flag;
Blackbox *blackbox = nullptr;

std::size_t round_up_to_nearest(std::size_t size, std::size_t align) {
  return (size + align - 1) & ~(align - 1);
}

void default_init() {
  try {
    init(0);
  } catch (const std::exception &ex) {
    std::cerr << "blackbox: fatal init failure: " << ex.what() << std::endl;
    std::abort();
  }
}

template <typename F> auto write_locked(F &&f) -> decltype(f()) {
  // Provides its own synchronization
  default_init();

  // Ensure only one writer is writing
  lock.lock();

  // Transition into write and prevent any previous stores from being
  // reordered after this increment.
  blackbox->sequence.fetch_add(1, std::memory_order_release);

  // Fence writes such that subsequent writes are not ordered before
  // prior sequence increment. The previous std::memory_order_release only
  // ensures prior writes are not ordered after the atomic operation.
  std::atomic_thread_fence(std::memory_order_release);

  // Write new entry
  auto retval = f();

  // Transition out of write and prevent any previous stores from being
  // reordered after this increment.
  //
  // Note we do not do additional fencing like above b/c we do not care
  // at this point if subsequent writes are ordered before the transition.
  blackbox->sequence.fetch_add(1, std::memory_order_release);

  // Pair with above lock()
  lock.unlock();

  return retval;
}

std::string get_shm_name() {
  auto pid = ::getpid();
  return std::format("/blackbox-{}", pid);
}

void cleanup() {
  // We actually want to recalculate this in case we were forked off from
  // the parent and exec() has not been called to clear the atexit() handlers
  // yet.
  auto shm_name = get_shm_name();
  ::shm_unlink(shm_name.c_str());
}

Header *header(std::uint64_t off) {
  auto data = blackbox->padding_start + blackbox->padding;
  return reinterpret_cast<Header *>(data + off);
}

Header *head() { return header(blackbox->head); }

Header *tail() {
  auto off = (blackbox->head + blackbox->size) % blackbox->psize;
  return header(off);
}

template <typename T> T *entry(Header *e) {
  return reinterpret_cast<T *>(e->data);
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
    std::uint64_t size = 0;
    auto h = head();

    switch (h->type) {
    case Type::Invalid:
      // Should never see an invalid entry if there's enough space
      return -EINVAL;
    case Type::String:
      size = entry<StringEntry>(h)->size();
      break;
    case Type::Int:
      size = entry<IntEntry>(h)->size();
      break;
    case Type::KeyValue:
      size= entry<KeyValueEntry>(h)->size();
      break;
    }

    blackbox->size -= size;
    blackbox->head = (blackbox->head + size) % blackbox->psize;
    evicted++;
  }

  return -ENOSYS;
}

// Inserts an entry into the ring buffer.
//
// Returns number of entries that had to be evicted.
int insert(Type type, void *entry, std::uint64_t size) {
  return write_locked([=]() {
    auto sz = sizeof(Header) + size;
    auto evicted = make_room_for(sz);
    if (evicted < 0) {
      return evicted;
    }

    auto header = tail();
    header->type = type;
    std::memcpy(header->data, entry, size);
    blackbox->size += size;

    return evicted;
  });
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

    // Give ring buffer PAGE_SIZE alignment so we can double map
    const std::size_t page_size = getpagesize();
    auto ring_size = size ? size : DEFAULT_SIZE;
    ring_size = round_up_to_nearest(ring_size, page_size);

    // Size segment to requested size.
    // NB: we give the header a full page to achieve alignment.
    if (::ftruncate(fd, page_size + ring_size) < 0) {
      throw std::system_error(errno, std::system_category(), "ftruncate");
    }

    // Reserve header + 2x ringbuffer address space to prevent races with
    // any other allocations the application might be doing.
    //
    // We're going to mmap the ring buffer twice so access is always linear
    // in our address space. This prevents TLV headers from being split
    // and thus allows reliable pointer casts.
    const auto addr_space_size = page_size + 2 * ring_size;
    auto ptr = static_cast<char *>(::mmap(nullptr, addr_space_size, PROT_NONE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (ptr == MAP_FAILED) {
      throw std::system_error(errno, std::system_category(), "mmap anon");
    }

    // Map first copy of ring buffer
    if (::mmap(ptr + page_size, ring_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED) {
      throw std::system_error(errno, std::system_category(), "mmap rb1");
    }

    // Map second copy of ring buffer at tail of first copy
    if (::mmap(ptr + page_size + ring_size, ring_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED) {
      throw std::system_error(errno, std::system_category(), "mmap rb2");
    }

    // Initialize the blackbox
    blackbox = reinterpret_cast<Blackbox *>(ptr);
    write_locked([page_size, ring_size]() {
      blackbox->head = 0;
      blackbox->size = 0;
      blackbox->psize = ring_size;
      blackbox->padding = page_size - sizeof(Blackbox);
      std::memset(blackbox->padding_start + blackbox->padding, 0, ring_size);

      // Hack to avoid dealing with void return type
      return 0;
    });
  });
}

int write(std::string_view s) noexcept {
  auto sz = sizeof(StringEntry) + s.size();
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<StringEntry *>(buffer.data());
  entry->len = s.size();
  std::memcpy(entry->string, s.data(), s.size());

  return insert(Type::String, entry, entry->size());
}

int write(std::int64_t i) noexcept {
  auto sz = sizeof(IntEntry);
  std::vector<std::uint8_t> buffer(sz);

  auto entry = reinterpret_cast<IntEntry *>(buffer.data());
  entry->val = i;

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

  return insert(Type::KeyValue, entry, entry->size());
}

int dump(std::ostream &out) {
  // Provides its own synchronization
  default_init();

  std::scoped_lock guard(lock);

  int dumped = 0;
  auto head = blackbox->head;
  while (head != (blackbox->head + blackbox->size)) {
    std::uint64_t size = sizeof(Header);
    auto hdr = header(head);

    switch (hdr->type) {
    case Type::Invalid:
      return -EINVAL;
    case Type::String: {
      auto str = entry<StringEntry>(hdr);
      out << std::string_view(str->string, str->len) << std::endl;
      size += entry<StringEntry>(hdr)->size();
      break;
    }
    case Type::Int: {
      auto i = entry<IntEntry>(hdr);
      out << i->val << std::endl;
      size += i->size();
      break;
    }
    case Type::KeyValue: {
      auto kv = entry<KeyValueEntry>(hdr);
      auto key = std::string_view(kv->data, kv->key_len);
      auto val = std::string_view(kv->data + kv->key_len, kv->val_len);
      out << std::format("{}={}", key, val) << std::endl;
      size += entry<KeyValueEntry>(hdr)->size();
      break;
    }
    }

    dumped++;
    head += size;
  }

  return dumped;
}

} // namespace blackbox

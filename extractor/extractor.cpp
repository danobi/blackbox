#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <functional>
#include <iostream>
#include <memory>

#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "internal.h"

using namespace blackbox::internal;

namespace {

void help() {
  std::cout << "Usage: extractor <pid> [options]\n"
            << "\nOptions:\n"
            << "  -h, --help Show this help message\n"
            << "\nArguments:\n"
            << "  pid        Process ID to extract\n"
            << std::endl;
}

// Copy the blackbox while inside assuming we're sequence locked.
//
// Note we also linearize the ring buffer to make reading easier
// without mucking with mmap. We're going to memcpy all the data
// anyways so this doesn't cost much more.
void copy_locked(Blackbox *copy, Blackbox *orig) {
  // Copy header
  ::memcpy(reinterpret_cast<void *>(copy), orig, sizeof(Blackbox));

  // Copy ring buffer out, linearizing if necessary
  auto orig_data = orig->padding_start + orig->padding;
  auto copy_data = copy->padding_start + copy->padding;
  if (orig->head + orig->size <= orig->psize) {
    ::memcpy(copy_data, orig_data + orig->head, orig->size);
  } else {
    auto linear = orig->psize - orig->head;
    ::memcpy(copy_data, orig_data + orig->head, linear);
    ::memcpy(copy_data + linear, orig_data, orig->size - linear);
  }
}

std::uint64_t read_seq(std::atomic_uint64_t &seq) {
  // memory_order_acquire is sufficient here b/c we only need ensure
  // subsequent loads are not reordered before the sequence load.
  //
  // The `& ~0x1` is just to ensure we retry in the event there is
  // a writer in the critical section. The sequence will be odd if
  // there is a write in progress.
  return seq.load(std::memory_order_acquire) & ~0x1ULL;
}

// Returns whether or not to retry the read critical section
bool read_retry(std::atomic_uint64_t &seq, std::uint64_t old_seq) {
  // memory_order_acq_rel is necessary here to ensure prior loads
  // are not reordered after the sequence load. memory_order_acquire
  // only guarantees subsequent loads are not reordered before the
  // sequence load, and not the other way around.
  //
  // If we see that the sequence was even _and_ unchanged before and
  // after the critical section, it means we got a consistent view
  // of the blackbox.
  std::atomic_thread_fence(std::memory_order_acq_rel);
  return seq.load(std::memory_order_relaxed) != old_seq;
}

// Copy blackbox from `orig` to `copy`.
//
// Returns whether or not a consistent copy was made.
bool copy(Blackbox *copy, Blackbox *orig) {
  int retries = 1000;
  std::uint64_t seq;
  bool retry;

  do {
    seq = read_seq(orig->sequence);
    copy_locked(copy, orig);
  } while ((retry = read_retry(orig->sequence, seq)) && --retries);

  return !retry;
}

std::unique_ptr<Blackbox, std::function<void(Blackbox *)>> grab(int pid) {
  // Open shared memory segment
  auto shm_name = std::format(BLACKBOX_SHM_FMTSTR, pid);
  auto fd = ::shm_open(shm_name.c_str(), O_RDONLY, 0);
  if (fd < 0) {
    auto err = std::strerror(errno);
    std::cerr << "Failed to shm_open(): " << err << std::endl;
    return nullptr;
  }

  // Get the size of the shared memory so we can mmap
  struct stat sb;
  if (::fstat(fd, &sb) == -1) {
    auto err = std::strerror(errno);
    std::cerr << "fstat failed: " << err << std::endl;
    ::close(fd);
    return nullptr;
  }

  // Map the shared memory into our address space
  auto ptr = ::mmap(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    auto err = std::strerror(errno);
    std::cerr << "mmap failed: " << err << std::endl;
    ::close(fd);
    return nullptr;
  }

  // Allocate enough memory to hold entire blackbox
  auto blackbox = static_cast<Blackbox *>(::malloc(sb.st_size));
  if (!blackbox) {
    auto err = std::strerror(ENOMEM);
    std::cerr << "malloc failed: " << err << std::endl;
    return nullptr;
  }

  // Copy out entire blackbox to minimize critical section.
  bool success = copy(blackbox, static_cast<Blackbox *>(ptr));

  // Done with shared memory
  ::munmap(ptr, sb.st_size);
  ::close(fd);

  if (success) {
    auto deleter = [&](Blackbox *p) { ::free(p); };
    return std::unique_ptr<Blackbox, decltype(deleter)>(blackbox, deleter);
  }

  return nullptr;
}

int dump(Blackbox *blackbox) {
  auto head = blackbox->head;
  auto tail = (blackbox->head + blackbox->size) % blackbox->psize;
  while (head != tail) {
    auto hdr = header(blackbox, head);

    switch (hdr->type) {
    case Type::String: {
      auto str = entry<StringEntry>(hdr);
      std::cout << std::string_view(str->string, str->len) << std::endl;
      break;
    }
    case Type::Int: {
      auto i = entry<IntEntry>(hdr);
      std::cout << i->val << std::endl;
      break;
    }
    case Type::KeyValue: {
      auto kv = entry<KeyValueEntry>(hdr);
      auto key = std::string_view(kv->data, kv->key_len);
      auto val = std::string_view(kv->data + kv->key_len, kv->val_len);
      std::cout << std::format("{}={}", key, val) << std::endl;
      break;
    }
    default:
      // Header::len gives us forward compatability.
      // If the target is using a newer version, we can just the new types.
      std::cout << "[unknown entry type]" << std::endl;
      break;
    }

    head = (head + hdr->size()) % blackbox->psize;
  }

  return 0;
}

bool is_alive(int pid) {
  return ::kill(pid, 0) == 0 || errno == EPERM;
}

int extract(int pid) {
  auto blackbox = grab(pid);
  if (!blackbox) {
    std::cerr << "Failed to extract blackbox from pid=" << pid << std::endl;
    return -1;
  }

  return dump(blackbox.get());
}

} // namespace

int main(int argc, char *argv[]) {
  struct option opts[] = {{"help", no_argument, 0, 'h'}, {}};

  int opt;
  while ((opt = getopt_long(argc, argv, "h", opts, nullptr)) != -1) {
    switch (opt) {
    case 'h':
      help();
      return 0;
    default:
      std::cerr << "Try 'extractor --help' for more information" << std::endl;
      return 1;
    }
  }

  if (optind >= argc) {
    std::cerr << "Error: PID is required" << std::endl;
    return 1;
  }

  int pid = std::stoi(argv[optind]);
  int ret = extract(pid);
  if (ret && !is_alive(pid)) {
    std::cerr << "Data loss -- process crashed during a write" << std::endl;
  }

  return ret;
}

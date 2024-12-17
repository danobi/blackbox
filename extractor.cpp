#include <cstdlib>
#include <cstring>
#include <format>
#include <functional>
#include <iostream>
#include <memory>

#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "internal.h"

using namespace blackbox::internal;

namespace {

void help() {
  std::cout << "Usage: extractor <pid> [options]\n"
            << "\nOptions:\n"
            << "  --force    Force extraction even if unsafe\n"
            << "  -h, --help Show this help message\n"
            << "\nArguments:\n"
            << "  pid        Process ID to extract\n"
            << std::endl;
}

// Copy blackbox starting at `from` of size `size` into `to`.
//
// Note we also linearize the ring buffer to make reading easier
// without mucking with mmap. We're going to memcpy all the data
// anyways so this doesn't cost much more.
void copy(Blackbox *copy, Blackbox *orig) {
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
    return nullptr;
  }

  // Map the shared memory into our address space
  auto ptr = ::mmap(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    auto err = std::strerror(errno);
    std::cerr << "mmap failed: " << err << std::endl;
    return nullptr;
  }

  // Allocate enough memory to hold entire blackbox
  auto blackbox = static_cast<Blackbox *>(::malloc(sb.st_size));

  // Copy out entire blackbox to minimize critical section.
  // XXX: respect sequence lock
  copy(blackbox, static_cast<Blackbox *>(ptr));

  auto deleter = [](Blackbox *p) { ::free(p); };
  return std::unique_ptr<Blackbox, decltype(deleter)>(blackbox, deleter);
}

int dump(Blackbox *blackbox, bool force) {
  (void)force;

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
    case Type::Invalid:
      return -1;
    }

    head = (head + hdr->size()) % blackbox->psize;
  }

  return 0;
}

int extract(int pid, bool force) {
  auto blackbox = grab(pid);
  if (!blackbox) {
    return -1;
  }

  return dump(blackbox.get(), force);
}

} // namespace

int main(int argc, char *argv[]) {
  bool force = false;

  struct option opts[] = {
      {"help", no_argument, 0, 'h'}, {"force", no_argument, 0, 'f'}, {}};

  int opt;
  while ((opt = getopt_long(argc, argv, "h", opts, nullptr)) != -1) {
    switch (opt) {
    case 'h':
      help();
      return 0;
    case 'f':
      force = true;
      break;
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
  return extract(pid, force);
}

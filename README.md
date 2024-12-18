# blackbox

`blackbox` is a flight recorder for your C++ application.

Once initialized, applications can write structured data to the in-memory
blackbox. This blackbox can then be extracted internally (API call) or
externally (by another process).

The internal extration is obvious, simple, and requires no explanation. The
external extraction is somewhat novel and has interesting properties.

For one, the external extractor does not require heavy-weight synchronization
from the application. Rather, the blackbox implementation uses shared memory
and lock-free techniques to guarantee non-blocking and consistent reads from
the application blackbox.

Furthermore, the blackbox is designed to be preserved after a crash. This is
similar to a real airplane blackbox. "Clean" (normal program termination) exit
from the application destroys the blackbox.

The API is documented in [blackbox.h](./blackbox.h).

## Demo

```
$ make
g++ -std=c++20 -Wall -Wextra -Werror -O3 extractor/extractor.cpp -I. -o extractor/extractor -g
g++ -std=c++20 -Wall -Wextra -Werror -O3 -fPIC -shared blackbox.cpp -o libblackbox.so -g
g++ -std=c++20 -Wall -Wextra -Werror -O3 demo/demo.cpp -L. -lblackbox -Wl,-rpath,. -I. -o demo/demo -g

$ ./demo/demo &

$ ./extractor/extractor $(pidof demo)
hello world!
123
key1=val1
```

## Features

* Structured data
* Thread-safe API
* In-process extraction
* Non-blocking out-of-process extraction (alive)
* Non-blocking out-of-process extraction (dead)
* Data consistency failsafes during extraction

## Interesting tricks

* Entries are TLV (tag-length-value) for extensibility
* Backing ringbuffer is mapped twice for always-linear access
* Shared memory (tmpfs) is used to not take kernel `mmap_lock` in application
* Implements a userspace sequence lock for data consistency

## TODO

- [ ] Tests (you dummy!)
- [ ] Check that wraparound codepaths actually work

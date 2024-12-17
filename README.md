# blackbox

XXX: blah

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

## TODO

- [ ] Tests (you dummy!)
- [ ] Check on if atexit() handlers run on segfault
- [ ] Cleanup on partial init

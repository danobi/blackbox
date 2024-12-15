# blackbox

XXX: blah

## Features

* Strongly typed data
* Thread-safe API
* In-process extraction
* Out-of-process extraction (alive)
* Out-of-process extraction (dead)
* Data consistency protection during extraction
* Non-blocking extraction

## Interesting tricks

* Entries are TLV (tag-length-value) for extensibility
* Backing ringbuffer is mapped twice for always-linear access

# DNS Benchmark

Linux-first Qt6 desktop tool for benchmarking DNS resolvers across UDP IPv4/IPv6, DNS-over-HTTPS, and DNS-over-TLS.

## Build

Requirements:

- CMake 3.24+
- C++20 compiler
- Qt6 Core, Network, Gui, Widgets, Charts, Test
- OpenSSL

```sh
cmake -S . -B build
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

## Run

```sh
./build/dnsbench
```

On startup the Linux detector reads DNS servers from `resolvectl status --json=short` when available, falling back to `/etc/resolv.conf`. Detected resolvers are pinned and enabled by default.

## Current Scope

Implemented for the Linux target first:

- Qt6 desktop UI with resolver table, protocol toggles, sample count, progress, ETA, conclusions, and log tabs.
- Add resolver dialog with protocol-aware validation.
- UDP, DoH, and DoT resolver backends.
- Warm-up sidelining before full benchmark runs.
- Statistics: median, mean, population stddev, min, max, and loss percent.
- Linux system DNS detection.
- CSV and plain-text export.
- QSettings persistence for user resolvers and UI settings.
- Unit tests for statistics, DNS packet construction, and Linux DNS detection parsing.

Windows and macOS detector/package work is intentionally deferred until the Linux path is solid.

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

### Windows Compile

Windows builds require Windows-targeted Qt6 and OpenSSL packages that match the
compiler/toolchain used for CMake. The Linux Qt packages installed on a build
host are not enough for cross-compiling. Wine can run the resulting Windows
binary or tests, but it does not provide the headers, import libraries, or CMake
package files needed to compile.

Example with MinGW and an existing Windows dependency prefix:

```sh
cmake -S . -B build-windows -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw64.cmake \
  -DDNSBENCH_WINDOWS_PREFIX=/path/to/windows-prefix \
  -DQT_HOST_PATH=/usr \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows
```

`/path/to/windows-prefix` must contain Windows-targeted Qt6 Charts and OpenSSL
CMake package files for the same MinGW triplet. `QT_HOST_PATH` should point at a
native Qt6 install when the target Qt package needs host tools such as `moc` and
`rcc`.

To try the same compile in a container, use the Fedora-based cross-build target:

```sh
docker buildx bake windows
```

The Windows compile path supports manual resolvers and detected system DNS
resolvers in both the GUI and headless mode.

### macOS Compile

Build macOS on a Mac with Xcode command line tools and Homebrew-provided Qt and
OpenSSL. Cross-compiling a usable macOS app bundle from Linux is not supported
because it needs Apple's SDK, frameworks, and deployment tooling.

```sh
xcode-select --install
brew install cmake ninja qt openssl@3 nlohmann-json
cmake -S . -B build-macos -G Ninja \
  "-DCMAKE_PREFIX_PATH=$(brew --prefix qt);$(brew --prefix openssl@3)" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-macos
ctest --test-dir build-macos --output-on-failure
```

The build produces `build-macos/dnsbench.app`. Manual and built-in resolvers
should work; `--system-dns` and the GUI system DNS action currently report that
platform detection is not implemented until a macOS detector is added.

## Run

```sh
./build/dnsbench
```

On startup the Linux detector reads DNS servers from `resolvectl status --json=short` when available, falling back to `/etc/resolv.conf`. Detected resolvers are pinned and enabled by default.

## Import Resolvers

Use `Import` in the toolbar to add many resolvers at once. Imported resolvers are treated like normal user-added resolvers and are saved in settings.

Supported file types:

- CSV: `.csv`
- TSV: `.tsv`
- Markdown tables: `.md`
- JSON: `.json`
- Plain text lists: `.txt`

CSV and TSV can use a header row:

```csv
name,address,protocol,port,pinned,enabled
Cloudflare,1.1.1.1,IPv4,53,false,true
Quad9 DoT,9.9.9.9,DoT,853,false,true
Google DoH,https://dns.google/dns-query,DoH,53,false,true
```

The importer also accepts exports from this app, including Markdown tables copied from `Copy Results`.

For quick lists, one resolver per line is enough. The protocol is inferred from the address when possible:

```text
1.1.1.1
2606:4700:4700::1111
https://cloudflare-dns.com/dns-query
dns.quad9.net
```

Loose rows with names and protocol are also accepted:

```text
Cloudflare IPv4,1.1.1.1,IPv4
Cloudflare DoH,https://cloudflare-dns.com/dns-query,DoH
Quad9 DoT,9.9.9.9,DoT,853
```

JSON can be either an array or an object with a `resolvers` array:

```json
{
  "resolvers": [
    {
      "name": "Cloudflare",
      "address": "1.1.1.1",
      "protocol": "IPv4"
    },
    {
      "name": "Quad9 DoT",
      "address": "9.9.9.9",
      "protocol": "DoT",
      "port": 853
    }
  ]
}
```

## Current Scope

Implemented for the Linux target first:

- Qt6 desktop UI with resolver table, protocol toggles, sample count, progress, ETA, results, and log tabs.
- Add resolver dialog with protocol-aware validation.
- Bulk resolver import from CSV, TSV, Markdown, JSON, and plain text lists.
- UDP, DoH, and DoT resolver backends.
- Warm-up sidelining before full benchmark runs.
- Statistics: median, p90, mean, population stddev, min, max, and loss percent.
- Per-resolver timeline sparklines with expandable charts.
- Linux system DNS detection.
- Built-in public resolver candidates from Cloudflare, Google, Quad9, OpenDNS, AdGuard, and Control D.
- CSV and Markdown export/copy.
- QSettings persistence for user resolvers and UI settings.
- Unit tests for statistics, DNS packet construction, and Linux DNS detection parsing.

Windows and macOS detector/package work is intentionally deferred until the Linux path is solid.

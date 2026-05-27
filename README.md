# DNS Benchmark

Qt6 desktop tool for benchmarking DNS resolvers across UDP IPv4/IPv6, DNS-over-HTTPS, and DNS-over-TLS.

## Features

- Resolver table with protocol filters, pinned resolvers, progress, ETA, logs, and result summaries.
- Built-in public resolver candidates from Cloudflare, Google, Quad9, OpenDNS, AdGuard, and Control D.
- System DNS detection on Linux, macOS, and Windows.
- UDP, DoH, and DoT resolver backends.
- Encrypted resolver connection warm-up and resolver sidelining before full benchmark runs.
- Cached and uncached measurements in the same run. Uncached queries use unique random labels under the configured site list, and completed `NXDOMAIN` replies count as valid DNS responses.
- Statistics: median, p90, mean, population stddev, min, max, and loss percent.
- Per-resolver timeline sparklines with expandable charts.
- Bulk resolver import from CSV, TSV, Markdown, JSON, and plain text.
- Test site import from Chromium-family browser history databases, including Chrome, Chromium, Brave, Edge, Vivaldi, and Opera profiles.
- CSV and Markdown export/copy.
- QSettings persistence for user resolvers, UI settings, and edited test site lists.

## Build

Requirements:

- CMake 3.24+
- C++20 compiler
- Qt6 Core, Network, Gui, Widgets, Charts, Sql, Test
- OpenSSL

```sh
cmake -S . -B build
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

Run the app:

```sh
./build/dnsbench
```

## Test Sites

The `Sites` menu controls the domains used for cached and uncached benchmark queries.

- `Import from Browser` reads recent Chromium-family browser history and replaces the site list with the top normalized domains.
- Browser import defaults to the top 100 domains from the last 30 days, ranked by visit and typed counts.
- `Save Test Sites` persists manual edits immediately.
- `Reset Test Sites` restores the bundled list.

Browser history is copied to a temporary SQLite file before reading, so normal locked browser profiles are handled without modifying the source database.

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

## Platform Builds

### Linux

Ubuntu packages needed for a local build include Qt Charts, Qt SQL SQLite support, OpenSSL, Ninja, and CMake:

```sh
sudo apt install build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools qt6-tools-dev qt6-tools-dev-tools libqt6charts6-dev libqt6sql6-sqlite libssl-dev nlohmann-json3-dev
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Container build:

```sh
docker buildx bake linux
```

### Windows

Windows builds require Windows-targeted Qt6 and OpenSSL packages that match the compiler/toolchain used for CMake. The Linux Qt packages installed on a build host are not enough for cross-compiling.

Example with MinGW and an existing Windows dependency prefix:

```sh
cmake -S . -B build-windows -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw64.cmake \
  -DDNSBENCH_WINDOWS_PREFIX=/path/to/windows-prefix \
  -DQT_HOST_PATH=/usr \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows
```

`/path/to/windows-prefix` must contain Windows-targeted Qt6 Charts, Qt6 Sql, and OpenSSL CMake package files for the same MinGW triplet. `QT_HOST_PATH` should point at a native Qt6 install when the target Qt package needs host tools such as `moc` and `rcc`.

Container cross-build:

```sh
docker buildx bake windows
```

### macOS

Build macOS on a Mac with Xcode command line tools and Homebrew-provided Qt and OpenSSL. Cross-compiling a usable macOS app bundle from Linux is not supported because it needs Apple's SDK, frameworks, and deployment tooling.

```sh
xcode-select --install
brew install cmake ninja qt openssl@3 nlohmann-json
cmake -S . -B build-macos -G Ninja \
  "-DCMAKE_PREFIX_PATH=$(brew --prefix qt);$(brew --prefix openssl@3)" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-macos
ctest --test-dir build-macos --output-on-failure
```

The build produces `build-macos/dnsbench.app`.

## Releases

The GitHub release workflow runs for tags matching `v*` and can also be started manually.

Release artifacts:

- `dnsbench-macos-universal.zip`: macOS `.app` bundle built as native Intel and Apple Silicon slices, merged with `lipo`, and packaged with `macdeployqt`.
- `dnsbench-linux-amd64.zip`: Linux amd64 build artifact.
- `dnsbench-linux-arm64.zip`: Linux arm64 build artifact.
- `dnsbench-windows-amd64.zip`: Windows amd64 executable with Qt/OpenSSL runtime DLLs and plugins.

The macOS artifact is ad-hoc signed only, not Developer ID signed or notarized. Users may need to allow it through Gatekeeper manually.

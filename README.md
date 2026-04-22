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

#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <dnsbench-executable> <qt-plugin-directory> <destination>" >&2
    exit 2
fi

executable=$1
qt_plugins=$2
destination=$3
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ ! -x $executable ]]; then
    echo "dnsbench executable is not runnable: $executable" >&2
    exit 1
fi
if [[ ! -d $qt_plugins ]]; then
    echo "Qt plugin directory does not exist: $qt_plugins" >&2
    exit 1
fi

mkdir -p "$destination/lib" "$destination/plugins"
cp -L "$executable" "$destination/dnsbench-bin"
cp "$script_dir/dnsbench.sh" "$destination/dnsbench"
chmod +x "$destination/dnsbench" "$destination/dnsbench-bin"

plugin_groups=(platforms tls sqldrivers imageformats networkinformation)
for group in "${plugin_groups[@]}"; do
    if [[ -d $qt_plugins/$group ]]; then
        cp -a "$qt_plugins/$group" "$destination/plugins/"
    fi
done

declare -A visited=()
queue=("$destination/dnsbench-bin")
while [[ ${#queue[@]} -gt 0 ]]; do
    current=${queue[0]}
    queue=("${queue[@]:1}")
    while IFS= read -r dependency; do
        [[ -n $dependency && -f $dependency ]] || continue
        name=$(basename -- "$dependency")
        case "$name" in
            ld-linux*.so.*|libc.so.*|libdl.so.*|libm.so.*|libpthread.so.*|librt.so.*|linux-vdso.so.*)
                continue
                ;;
        esac
        [[ -z ${visited[$name]+x} ]] || continue
        visited[$name]=1
        cp -L "$dependency" "$destination/lib/$name"
        queue+=("$dependency")
    done < <(ldd "$current" | awk '/=> \// { print $3 } /^\// { print $1 }')
done

while IFS= read -r plugin; do
    queue=("$plugin")
    while [[ ${#queue[@]} -gt 0 ]]; do
        current=${queue[0]}
        queue=("${queue[@]:1}")
        while IFS= read -r dependency; do
            [[ -n $dependency && -f $dependency ]] || continue
            name=$(basename -- "$dependency")
            case "$name" in
                ld-linux*.so.*|libc.so.*|libdl.so.*|libm.so.*|libpthread.so.*|librt.so.*|linux-vdso.so.*)
                    continue
                    ;;
            esac
            [[ -z ${visited[$name]+x} ]] || continue
            visited[$name]=1
            cp -L "$dependency" "$destination/lib/$name"
            queue+=("$dependency")
        done < <(ldd "$current" | awk '/=> \// { print $3 } /^\// { print $1 }')
    done
done < <(find "$destination/plugins" -type f -name '*.so')

cp "$script_dir/dnsbench.desktop" "$destination/"
cp "$script_dir/../../resources/dnsbench.svg" "$destination/"

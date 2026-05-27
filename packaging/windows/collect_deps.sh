#!/bin/bash
set -e

EXE_PATH=$1
MINGW_BIN=$2
MINGW_PLUGINS=$3
DEST_DIR=$4

mkdir -p "$DEST_DIR"

# Copy main executable
cp "$EXE_PATH" "$DEST_DIR/"

# List of DLLs to check for dependencies
check_list=("$EXE_PATH")
copied_dlls=()

# Function to get dependencies of a DLL/EXE
get_deps() {
    x86_64-w64-mingw32-objdump -p "$1" | grep "DLL Name:" | awk '{print $3}'
}

# Recursively find and copy dependencies
while [ ${#check_list[@]} -gt 0 ]; do
    current="${check_list[0]}"
    check_list=("${check_list[@]:1}")
    
    deps=$(get_deps "$current")
    for dep in $deps; do
        if [[ ! " ${copied_dlls[@]} " =~ " ${dep} " ]]; then
            dep_path="$MINGW_BIN/$dep"
            if [ -f "$dep_path" ]; then
                cp "$dep_path" "$DEST_DIR/"
                copied_dlls+=("$dep")
                check_list+=("$dep_path")
                echo "Copied dependency: $dep"
            fi
        fi
    done
done

# Copy Qt plugins
mkdir -p "$DEST_DIR/platforms"
cp "$MINGW_PLUGINS/platforms/qwindows.dll" "$DEST_DIR/platforms/"

mkdir -p "$DEST_DIR/tls"
cp "$MINGW_PLUGINS/tls/qopensslbackend.dll" "$DEST_DIR/tls/"
cp "$MINGW_PLUGINS/tls/qschannelbackend.dll" "$DEST_DIR/tls/"
cp "$MINGW_PLUGINS/tls/qcertonlybackend.dll" "$DEST_DIR/tls/"

mkdir -p "$DEST_DIR/networkinformation"
cp "$MINGW_PLUGINS/networkinformation/qnetworklistmanager.dll" "$DEST_DIR/networkinformation/"

mkdir -p "$DEST_DIR/sqldrivers"
cp "$MINGW_PLUGINS/sqldrivers/qsqlite.dll" "$DEST_DIR/sqldrivers/"

# Image formats plugins
cp "$MINGW_PLUGINS/imageformats/qico.dll" "$DEST_DIR/imageformats/"
cp "$MINGW_PLUGINS/imageformats/qgif.dll" "$DEST_DIR/imageformats/"
cp "$MINGW_PLUGINS/imageformats/qjpeg.dll" "$DEST_DIR/imageformats/"

# Explicitly copy OpenSSL DLLs (Qt loads them dynamically)
cp "$MINGW_BIN/libssl-3-x64.dll" "$DEST_DIR/" || echo "Warning: libssl-3-x64.dll not found"
cp "$MINGW_BIN/libcrypto-3-x64.dll" "$DEST_DIR/" || echo "Warning: libcrypto-3-x64.dll not found"

# Also check dependencies of plugins
for plugin in $(find "$DEST_DIR" -name "*.dll"); do
    deps=$(get_deps "$plugin")
    for dep in $deps; do
        if [[ ! " ${copied_dlls[@]} " =~ " ${dep} " ]]; then
            dep_path="$MINGW_BIN/$dep"
            if [ -f "$dep_path" ]; then
                cp "$dep_path" "$DEST_DIR/"
                copied_dlls+=("$dep")
                echo "Copied plugin dependency: $dep"
            fi
        fi
    done
done

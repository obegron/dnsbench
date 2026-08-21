# syntax=docker/dockerfile:1.7

FROM ubuntu:24.04 AS linux-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    libcurl4-openssl-dev \
    libqt6charts6-dev \
    libqt6sql6-sqlite \
    libssl-dev \
    ninja-build \
    nlohmann-json3-dev \
    pkg-config \
    qt6-base-dev \
    qt6-base-dev-tools \
    qt6-tools-dev \
    qt6-tools-dev-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY . .

RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release
RUN cmake --build /build

ENV QT_QPA_PLATFORM=offscreen

RUN ctest --test-dir /build --output-on-failure

RUN chmod +x /src/packaging/linux/collect_deps.sh /src/packaging/linux/dnsbench.sh && \
    /src/packaging/linux/collect_deps.sh \
        /build/dnsbench \
        "/usr/lib/$(gcc -dumpmachine)/qt6/plugins" \
        /build/linux-bundle

FROM scratch AS linux-artifacts

COPY --from=linux-build /build/linux-bundle /dnsbench

FROM fedora:42 AS windows-build

RUN dnf install -y --setopt=install_weak_deps=False \
    cmake \
    gcc-c++ \
    mingw64-gcc-c++ \
    mingw64-curl \
    mingw64-openssl \
    mingw64-qt6-qtbase \
    mingw64-qt6-qtcharts \
    mingw64-sqlite \
    ninja-build \
    qt6-qtbase-devel \
    qt6-qttools-devel \
    mingw-nsis-base \
    mingw32-nsis \
    mingw64-nsis \
    && dnf clean all

WORKDIR /src

COPY . .

RUN cmake -S . -B /build/windows -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=/src/cmake/toolchains/mingw64.cmake \
    -DMINGW_ROOT=/usr/x86_64-w64-mingw32/sys-root/mingw \
    -DDNSBENCH_WINDOWS_PREFIX=/usr/x86_64-w64-mingw32/sys-root/mingw \
    -DQT_HOST_PATH=/usr \
    -DCMAKE_BUILD_TYPE=Release
RUN cmake --build /build/windows

# Collect dependencies and build installer
RUN mkdir -p /build/windows/dist && \
    chmod +x /src/packaging/windows/collect_deps.sh && \
    /src/packaging/windows/collect_deps.sh \
        /build/windows/dnsbench.exe \
        /usr/x86_64-w64-mingw32/sys-root/mingw/bin \
        /usr/x86_64-w64-mingw32/sys-root/mingw/lib/qt6/plugins \
        /build/windows/dist && \
    cp /src/packaging/windows/dnsbench.nsi /build/windows/ && \
    cd /build/windows && makensis dnsbench.nsi

FROM scratch AS windows-artifacts

COPY --from=windows-build /build/windows/dnsbench-setup.exe /dnsbench-setup.exe
COPY --from=windows-build /build/windows/dist /dist

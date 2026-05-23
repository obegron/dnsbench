# syntax=docker/dockerfile:1.7

FROM ubuntu:24.04 AS linux-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    libqt6charts6-dev \
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

FROM fedora:42 AS windows-build

RUN dnf install -y --setopt=install_weak_deps=False \
    cmake \
    gcc-c++ \
    mingw64-gcc-c++ \
    mingw64-openssl \
    mingw64-qt6-qtbase \
    mingw64-qt6-qtcharts \
    ninja-build \
    qt6-qtbase-devel \
    qt6-qttools-devel \
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

FROM scratch AS windows-artifacts

ARG MINGW_BIN=/usr/x86_64-w64-mingw32/sys-root/mingw/bin
ARG MINGW_PLUGINS=/usr/x86_64-w64-mingw32/sys-root/mingw/lib/qt6/plugins

COPY --from=windows-build ${MINGW_BIN}/libgcc_s_seh-1.dll /libgcc_s_seh-1.dll
COPY --from=windows-build ${MINGW_BIN}/libstdc++-6.dll /libstdc++-6.dll
COPY --from=windows-build ${MINGW_BIN}/libwinpthread-1.dll /libwinpthread-1.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6Charts.dll /Qt6Charts.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6Core.dll /Qt6Core.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6Gui.dll /Qt6Gui.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6Network.dll /Qt6Network.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6Widgets.dll /Qt6Widgets.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6OpenGL.dll /Qt6OpenGL.dll
COPY --from=windows-build ${MINGW_BIN}/Qt6OpenGLWidgets.dll /Qt6OpenGLWidgets.dll
COPY --from=windows-build ${MINGW_BIN}/libpcre2-8-0.dll /libpcre2-8-0.dll
COPY --from=windows-build ${MINGW_BIN}/libpcre2-32-0.dll /libpcre2-32-0.dll
COPY --from=windows-build ${MINGW_BIN}/libpcre2-posix-3.dll /libpcre2-posix-3.dll
COPY --from=windows-build ${MINGW_BIN}/libharfbuzz-cairo-0.dll /libharfbuzz-cairo-0.dll
COPY --from=windows-build ${MINGW_BIN}/libharfbuzz-gobject-0.dll /libharfbuzz-gobject-0.dll
COPY --from=windows-build ${MINGW_BIN}/libharfbuzz-icu-0.dll /libharfbuzz-icu-0.dll
COPY --from=windows-build ${MINGW_BIN}/libharfbuzz-subset-0.dll /libharfbuzz-subset-0.dll
COPY --from=windows-build ${MINGW_BIN}/icuio76.dll /icuio76.dll
COPY --from=windows-build ${MINGW_BIN}/icutest76.dll /icutest76.dll
COPY --from=windows-build ${MINGW_BIN}/icutu76.dll /icutu76.dll
COPY --from=windows-build ${MINGW_BIN}/zlib1.dll /zlib1.dll
COPY --from=windows-build ${MINGW_BIN}/libpcre2-16-0.dll /libpcre2-16-0.dll
COPY --from=windows-build ${MINGW_BIN}/libcrypto-3-x64.dll /libcrypto-3-x64.dll
COPY --from=windows-build ${MINGW_BIN}/libssl-3-x64.dll /libssl-3-x64.dll
COPY --from=windows-build ${MINGW_BIN}/libharfbuzz-0.dll /libharfbuzz-0.dll
COPY --from=windows-build ${MINGW_BIN}/libpng16-16.dll /libpng16-16.dll
COPY --from=windows-build ${MINGW_BIN}/libjpeg-62.dll /libjpeg-62.dll
COPY --from=windows-build ${MINGW_BIN}/libfreetype-6.dll /libfreetype-6.dll
COPY --from=windows-build ${MINGW_BIN}/libglib-2.0-0.dll /libglib-2.0-0.dll
COPY --from=windows-build ${MINGW_BIN}/libintl-8.dll /libintl-8.dll
COPY --from=windows-build ${MINGW_BIN}/iconv.dll /iconv.dll
COPY --from=windows-build ${MINGW_BIN}/libfontconfig-1.dll /libfontconfig-1.dll
COPY --from=windows-build ${MINGW_BIN}/libexpat-1.dll /libexpat-1.dll
COPY --from=windows-build ${MINGW_BIN}/libbz2-1.dll /libbz2-1.dll
COPY --from=windows-build ${MINGW_BIN}/icudata76.dll /icudata76.dll
COPY --from=windows-build ${MINGW_BIN}/icui18n76.dll /icui18n76.dll
COPY --from=windows-build ${MINGW_BIN}/icuuc76.dll /icuuc76.dll
COPY --from=windows-build ${MINGW_PLUGINS}/platforms/qwindows.dll /platforms/qwindows.dll
COPY --from=windows-build ${MINGW_PLUGINS}/tls/qopensslbackend.dll /tls/qopensslbackend.dll
COPY --from=windows-build ${MINGW_PLUGINS}/tls/qschannelbackend.dll /tls/qschannelbackend.dll
COPY --from=windows-build ${MINGW_PLUGINS}/tls/qcertonlybackend.dll /tls/qcertonlybackend.dll
COPY --from=windows-build ${MINGW_PLUGINS}/networkinformation/qnetworklistmanager.dll /networkinformation/qnetworklistmanager.dll
COPY --from=windows-build ${MINGW_PLUGINS}/imageformats/qico.dll /imageformats/qico.dll
COPY --from=windows-build ${MINGW_PLUGINS}/imageformats/qgif.dll /imageformats/qgif.dll
COPY --from=windows-build ${MINGW_PLUGINS}/imageformats/qjpeg.dll /imageformats/qjpeg.dll


COPY --from=windows-build /build/windows/dnsbench.exe /dnsbench.exe
COPY --from=windows-build /build/windows/test_statistics.exe /test_statistics.exe
COPY --from=windows-build /build/windows/test_dns_packet.exe /test_dns_packet.exe
COPY --from=windows-build /build/windows/test_udp_benchmark.exe /test_udp_benchmark.exe

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


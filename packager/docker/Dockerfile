# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors
#
# Build environment for one target distro. packager/build.py (ensure_image) builds it as nginx-clientfp-build:<target>.
# The integration tests also run the ./build.sh asan and ./build.sh valgrind nginx builds in it, hence valgrind.
ARG BASE=ubuntu:24.04
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential debhelper dpkg-dev fakeroot lintian perl python3 \
        libpcre2-dev zlib1g-dev libssl-dev binutils file git ca-certificates \
        valgrind \
 && rm -rf /var/lib/apt/lists/*

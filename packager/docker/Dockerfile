# Build environment for one target distro. packager/docker.py builds it as nginx-clientfp-build:<target>.
ARG BASE=ubuntu:24.04
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential debhelper dpkg-dev fakeroot lintian perl python3 \
        libpcre2-dev zlib1g-dev binutils file git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

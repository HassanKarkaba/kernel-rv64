# Reference reconstruction recipe. Qualification is NOT RUN until this image is built and all gates execute.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ARG DEBIAN_FRONTEND=noninteractive
ARG APT_SNAPSHOT=20261106T000000Z
ENV SOURCE_DATE_EPOCH=1793923200
# The minimal base has no CA bundle. BuildKit verifies HTTPS and this package hash
# before its public trust roots bootstrap the signed HTTPS package snapshot.
ADD --checksum=sha256:641de77d8f142cfd62a1a6f964ba67b20754d3337c480efb529d086075a06c9a https://snapshot.ubuntu.com/ubuntu/20261106T000000Z/pool/main/c/ca-certificates/ca-certificates_20240203_all.deb /tmp/bootstrap-ca.deb
RUN dpkg-deb -x /tmp/bootstrap-ca.deb /tmp/bootstrap-ca && mkdir -p /etc/ssl/certs && \
    cat /tmp/bootstrap-ca/usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt && \
    rm -rf /tmp/bootstrap-ca /tmp/bootstrap-ca.deb
RUN printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/%s/\nSuites: noble noble-updates noble-security\nComponents: main universe\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' "$APT_SNAPSHOT" > /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update -o APT::Update::Error-Mode=any && \
    apt-get install -y --no-install-recommends \
    ca-certificates curl git make gcc g++ pkg-config ninja-build \
    libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev \
    gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu gdb-multiarch \
    python3.12 python3.12-venv xz-utils && \
    rm -rf /var/lib/apt/lists/*
RUN apt-get update -o APT::Update::Error-Mode=any && \
    apt-get install -y --no-install-recommends bzip2 && rm -rf /var/lib/apt/lists/*
COPY requirements.lock containers/requirements-build.lock /tmp/
RUN python3.12 -m venv /opt/python && \
    /opt/python/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock -r /tmp/requirements-build.lock
COPY toolchain.lock /tmp/toolchain.lock
COPY containers/bootstrap.py /tmp/bootstrap.py
ENV PATH=/opt/kernel-tools/rust/bin:/opt/kernel-tools/qemu/bin:/opt/python/bin:$PATH
RUN /opt/python/bin/python /tmp/bootstrap.py && useradd --uid 10001 --create-home builder && \
    mkdir -p /evidence && chown builder:builder /evidence
ENV OPENSBI_SOURCE=/opt/tool-sources/opensbi-1.7
ENV CROSS_COMPILE=riscv64-linux-gnu-
ENV CARGO_HOME=/src/build/cargo-home
COPY --chown=builder:builder . /src
WORKDIR /src
USER builder
RUN ./scripts/build.sh && \
    python3 tools/doctor.py --firmware build/fw_dynamic.bin --output /evidence/tool-identities.json
CMD ["bash"]

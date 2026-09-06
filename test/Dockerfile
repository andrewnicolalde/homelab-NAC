# ==============================================================================
# Dockerfile for eapol_test (wpa_supplicant) with CNSA Suite B 192-bit support
# ==============================================================================
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
    build-base \
    openssl-dev \
    libnl3-dev \
    linux-headers \
    tar \
    pkgconf \
    dbus-dev

WORKDIR /build
ARG WPA_SUPPLICANT_VERSION=2.12

# Copy vendored upstream source archive which forms part of this repo for deterministic offline builds
COPY wpa_supplicant-${WPA_SUPPLICANT_VERSION}.tar.gz /build/

RUN tar -xzf wpa_supplicant-${WPA_SUPPLICANT_VERSION}.tar.gz && \
    cd wpa_supplicant-${WPA_SUPPLICANT_VERSION}/wpa_supplicant && \
    cp defconfig .config && \
    echo "CONFIG_EAPOL_TEST=y" >> .config && \
    echo "CONFIG_SUITEB192=y" >> .config && \
    make -j$(nproc) eapol_test && \
    install -m 755 eapol_test /usr/local/bin/eapol_test

FROM alpine:3.20
RUN apk add --no-cache openssl libnl3 dbus-libs
COPY --from=builder /usr/local/bin/eapol_test /usr/local/bin/eapol_test

ENTRYPOINT ["eapol_test"]
CMD ["-h"]

# ==============================================================================
# Dockerfile for eapol_test (wpa_supplicant) with CNSA Suite B 192-bit support
# Post-quantum (hybrid ML-KEM) EAP-TLS 1.3 testing needs OpenSSL >= 3.5 at
# runtime: build with --build-arg ALPINE_VERSION=3.24.1 (see eapol_test-pqc.conf)
# ==============================================================================
ARG ALPINE_VERSION=3.20
FROM alpine:${ALPINE_VERSION} AS builder

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

# CONFIG_RADIUS_TLS adds RADIUS over TLS (RadSec) to eapol_test (-X TLS, with
# -j/-J/-k for the CA, client certificate and key): hostapd's RADIUS client,
# so the tests can stand in for an access point's RadSec connection.
RUN tar -xzf wpa_supplicant-${WPA_SUPPLICANT_VERSION}.tar.gz && \
    cd wpa_supplicant-${WPA_SUPPLICANT_VERSION}/wpa_supplicant && \
    cp defconfig .config && \
    echo "CONFIG_EAPOL_TEST=y" >> .config && \
    echo "CONFIG_SUITEB192=y" >> .config && \
    echo "CONFIG_RADIUS_TLS=y" >> .config && \
    make -j$(nproc) eapol_test && \
    install -m 755 eapol_test /usr/local/bin/eapol_test

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache openssl libnl3 dbus-libs
COPY --from=builder /usr/local/bin/eapol_test /usr/local/bin/eapol_test

ENTRYPOINT ["eapol_test"]
CMD ["-h"]

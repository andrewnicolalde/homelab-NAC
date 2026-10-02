# FreeRADIUS 3.2.10 built from the upstream release tarball. Alpine only
# packages 3.0.x and the upstream images are amd64-only, so this builds for
# every platform requested (linux/arm64, linux/amd64) against Alpine's OpenSSL
# (>= 3.5, required for the post-quantum groups in k8s-pqc/).

# alpine:3.24.1 (multi-arch index)
ARG ALPINE_IMAGE=alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM ${ALPINE_IMAGE} AS build

ARG FREERADIUS_URL=https://github.com/FreeRADIUS/freeradius-server/releases/download/release_3_2_10/freeradius-server-3.2.10.tar.gz
# Digest of freeradius-server-3.2.10.tar.gz as published on the GitHub release
ARG FREERADIUS_SHA256=40e0cdfdcceb22cf0acb79bc29cf7c32995466a61fda09445ce5220608a55afd

RUN apk add --no-cache gcc make libc-dev linux-headers talloc-dev openssl-dev binutils

WORKDIR /src

# Download the release and refuse to build unless it matches the digest above.
# On a mismatch (or a failed download) this step exits with an error, the whole
# build stops, and nothing from the download reaches any image.
RUN wget -q -O freeradius.tar.gz "${FREERADIUS_URL}" \
    && if ! echo "${FREERADIUS_SHA256}  freeradius.tar.gz" | sha256sum -c -; then \
           echo "SECURITY ERROR: freeradius.tar.gz does not match FREERADIUS_SHA256." >&2; \
           echo "  expected: ${FREERADIUS_SHA256}" >&2; \
           echo "  actual:   $(sha256sum freeradius.tar.gz | cut -d' ' -f1)" >&2; \
           echo "The download may have been tampered with. Refusing to build." >&2; \
           exit 1; \
       fi \
    && tar -xzf freeradius.tar.gz --strip-components=1 \
    && rm freeradius.tar.gz

# Only talloc and OpenSSL are available, so modules needing other libraries
# (SQL, LDAP, Perl, Python, REST, ...) are not built.
RUN ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --mandir=/usr/share/man \
        --with-experimental-modules=no \
    && make -j"$(nproc)"

# PACKAGE=yes skips generating the upstream test certificates; the real ones
# are mounted from the freeradius-certs Secret. The eap module is mounted per
# deployment (k8s/config/eap, k8s-pqc/config/eap), so its default link is
# removed. /var is recreated in the final stage, keeping Alpine's /var/run
# symlink intact.
RUN make install R=/rootfs PACKAGE=yes \
    && rm -rf /rootfs/usr/include /rootfs/usr/share/man /rootfs/usr/share/doc /rootfs/var \
    && rm -f /rootfs/usr/lib/*.a /rootfs/usr/lib/*.la \
    && find /rootfs/etc/raddb/certs -mindepth 1 -delete \
    && rm /rootfs/etc/raddb/mods-enabled/eap \
    && find /rootfs/usr/sbin /rootfs/usr/bin /rootfs/usr/lib -type f \
        -exec sh -c 'head -c4 "$1" | grep -q ELF && strip --strip-unneeded "$1"' _ {} \;

# Our own radiusd.conf: the stock settings with proxying turned off (see the
# file). It is shipped as the image's default and also mounted by the
# Deployments, so it can change without rebuilding the image. proxy.conf is
# never read, so it is removed. Ownership and mode are set with the rest of
# /etc/raddb in the final stage. Built with the repository root as context
# (see /.dockerignore).
COPY k8s/config/radiusd.conf /rootfs/etc/raddb/radiusd.conf
RUN rm /rootfs/etc/raddb/proxy.conf

FROM ${ALPINE_IMAGE}

RUN apk add --no-cache talloc libssl3 libcrypto3 \
    && addgroup -S -g 101 radius \
    && adduser -S -D -H -u 100 -G radius -h /var/lib/radiusd -s /sbin/nologin radius

COPY --from=build /rootfs/ /

# Config readable by radius but not writable; runtime directories writable.
RUN chown -R root:radius /etc/raddb \
    && find /etc/raddb -type d -exec chmod 0750 {} + \
    && find /etc/raddb -type f -exec chmod 0640 {} + \
    && install -d -o radius -g radius -m 0750 /var/log/radius /var/log/radius/radacct /run/radiusd /var/lib/radiusd

# Run as the unprivileged radius user (UID 100, GID 101, matching the Deployments)
USER radius

EXPOSE 1812/udp 1813/udp 2083/tcp

ENTRYPOINT ["radiusd"]
# Foreground, logging to stdout. Debug output (-X) is opt-in because it
# prints the MS-MPPE session keys of every Access-Accept.
CMD ["-f", "-l", "stdout"]

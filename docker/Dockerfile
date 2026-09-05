FROM alpine:latest

# Install official Alpine packages for FreeRADIUS (compiled for aarch64 on arm64 hardware)
RUN apk add --no-cache \
    freeradius \
    freeradius-eap \
    freeradius-utils

# Run as the unprivileged built-in radius user (UID 100)
USER radius

EXPOSE 1812/udp 1813/udp 2083/tcp

ENTRYPOINT ["radiusd"]
CMD ["-X"]

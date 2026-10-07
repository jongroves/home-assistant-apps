FROM ghcr.io/home-assistant/base:latest@sha256:59c99f645cd5bc2e20ca8acac0a6a6163749720e1a1fcdd49bcb5702b5db9688

RUN apk add --no-cache python3

COPY rootfs /
COPY run.sh /run.sh
RUN chmod 0755 /run.sh

CMD ["/run.sh"]

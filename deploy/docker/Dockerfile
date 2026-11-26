# sber-cert-master as a container: the keeper writes tokens/TLS files to a shared volume that
# agent containers mount read-only. Build from the repository root:
#   docker build -f deploy/docker/Dockerfile -t sber-cert-master .
FROM alpine:3.22
RUN apk add --no-cache python3 openssl ca-certificates tzdata \
 && addgroup -g 10050 sber-agents \
 && addgroup -g 10051 sber-cert-master \
 && adduser -D -H -u 10051 -G sber-cert-master -s /sbin/nologin sber-cert-master \
 && addgroup sber-cert-master sber-agents \
 && mkdir -p /var/lib/sber-cert-master/state /var/lib/sber-cert-master/public /var/lib/sber-cert-master/incoming /etc/sber-cert-master \
 && chown -R sber-cert-master:sber-cert-master /var/lib/sber-cert-master \
 && chmod 0700 /var/lib/sber-cert-master/state /var/lib/sber-cert-master/incoming \
 && chmod 0755 /var/lib/sber-cert-master/public
COPY sber_cert_master /opt/sber-cert-master/sber_cert_master
ENV PYTHONPATH=/opt/sber-cert-master \
    PYTHONUNBUFFERED=1 \
    SBER_CERT_MASTER_CONFIG=/etc/sber-cert-master/config.toml
USER sber-cert-master
WORKDIR /var/lib/sber-cert-master
# Watchdog: unhealthy if the loop stopped ticking or the published token is about to expire.
HEALTHCHECK --interval=2m --timeout=30s --start-period=2m --retries=2 \
  CMD python3 -m sber_cert_master check >/dev/null || exit 1
ENTRYPOINT ["python3", "-m", "sber_cert_master"]
CMD ["run"]

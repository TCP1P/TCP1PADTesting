FROM debian:bookworm-slim

# Keep out of the host's daily `docker image prune -af` (the prune cron
# excludes label org.gzctf.keep=true).
LABEL org.gzctf.keep="true"

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat supervisor iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY vault.c /app/vault.c
# Deliberately weak mitigations so the use-after-free is exploitable as an
# arbitrary read:
#   -fno-stack-protector  no stack canary
#   -no-pie -fno-pic      fixed addresses -> g_flag is a stable target
#   -z norelro            writable GOT
# No execstack: the exploit path is an arbitrary read of the fixed-address flag,
# not shellcode.
RUN gcc -fno-stack-protector -no-pie -fno-pic -z norelro \
        -O0 -g -o /app/vault /app/vault.c \
    && chmod +x /app/vault
COPY supervisord.conf /etc/supervisord.conf

# No baked flag: the platform supplies the live flag at $GZCTF_FLAG_FILE
# (Docker: /flag bind-mount; K8s: /gzctf-flag/flag via the flag-pull sidecar).
# g_flag is loaded fresh on each process start; a missing/empty file = warmup.
EXPOSE 9000
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

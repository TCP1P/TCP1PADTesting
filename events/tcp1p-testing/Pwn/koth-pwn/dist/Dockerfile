FROM debian:bookworm-slim

# Keep out of the host's daily `docker image prune -af` (excludes this label).
LABEL org.gzctf.keep="true"

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat supervisor \
    && rm -rf /var/lib/apt/lists/*

# KotH has no per-team flag — the only platform contract is the marker file
# /koth/king (read each tick to decide the king). Pre-create the dir so
# do_crown() can write it from the first connection.
RUN mkdir -p /koth

WORKDIR /app
COPY hill.c /app/hill.c
# Deliberately weak mitigations so the bugs are exploitable:
#   -fno-stack-protector  no canary       (#1 ret overwrite)
#   -no-pie -fno-pic      fixed addresses (do_crown / is_admin stable targets)
#   -z norelro            writable GOT
#   -z execstack          executable stack
RUN gcc -fno-stack-protector -no-pie -fno-pic -z norelro -z execstack \
        -O0 -g -o /app/hill /app/hill.c \
    && chmod +x /app/hill
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 9000
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

FROM debian:bookworm-slim

# Keep out of the host's daily `docker image prune -af` (the prune cron
# excludes label org.gzctf.keep=true).
LABEL org.gzctf.keep="true"

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat supervisor iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY armory.c /app/armory.c
# Deliberately weak mitigations so the memory-corruption bugs are exploitable:
#   -fno-stack-protector  no stack canary (bug #1 ret overwrite)
#   -no-pie -fno-pic      fixed addresses -> print_flag() is a stable target
#   -z norelro            writable GOT
#   -z execstack          executable stack (classic shellcode path)
RUN gcc -fno-stack-protector -no-pie -fno-pic -z norelro -z execstack \
        -O0 -g -o /app/armory /app/armory.c \
    && chmod +x /app/armory
COPY supervisord.conf /etc/supervisord.conf

# No baked flag: the platform supplies the live flag at $GZCTF_FLAG_FILE
# (Docker: /flag bind-mount; K8s: /gzctf-flag/flag via the flag-pull sidecar).
# print_flag() reads it fresh on each disclosure; a missing file = warmup.
EXPOSE 9000
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

# Python 3.9: PyYAML 3.13 (the deliberately-outdated A06 component) relies on
# collections.Hashable, removed in 3.10+ — on 3.10+ the YAML feature breaks at
# runtime. 3.9 keeps it working AND keeps yaml.load() unsafe (RCE).
FROM python:3.9-slim

# Keep out of the host's daily `docker image prune -af` (excludes this label).
LABEL org.gzctf.keep="true"

# supervisor as PID 1 (see supervisord.conf) so a botched exploit that crashes
# the service doesn't drop the shared hill — supervisord respawns it in place.
RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor \
    && rm -rf /var/lib/apt/lists/*

# KotH has no per-team flag. The only platform contract is the marker file
# /koth/king (read each tick to decide the king). Pre-create the dir so the
# crown can write the marker from the first tick.
RUN mkdir -p /koth

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/app.py
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 8080
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

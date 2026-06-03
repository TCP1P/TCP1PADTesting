FROM python:3.11-slim

# Keep out of the host's daily `docker image prune -af` (the prune cron excludes
# label org.gzctf.keep=true).
LABEL org.gzctf.keep="true"

# supervisor as PID 1 (see supervisord.conf) so the container survives the
# service process dying or being restarted in place.
RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/app.py
COPY supervisord.conf /etc/supervisord.conf

# No baked flag: this is a jeopardy DynamicContainer, so the platform injects the
# per-team flag as the $GZCTF_FLAG environment variable. app.py reads it per
# request; a missing var falls back to a local-test placeholder.
EXPOSE 8080
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

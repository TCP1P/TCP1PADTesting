FROM python:3.11-alpine

# Keep this image out of the host's daily `docker image prune -af` — the
# checker is spawned per tick with no long-running container holding it, so an
# aggressive prune would delete it and every check would fail to pull
# (InternalError). The prune cron excludes label org.gzctf.keep=true.
LABEL org.gzctf.keep="true"

COPY check.py /check.py
RUN chmod +x /check.py

# enochecker3 exit-code contract: 0=Ok, 1=Mumble, 2=Offline, 3=InternalError.
# Reads GZCTF_TARGET_IP / GZCTF_TARGET_PORT.
ENTRYPOINT ["python3", "/check.py"]

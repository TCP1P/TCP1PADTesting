FROM python:3.11-alpine

# Keep this image out of the host's daily `docker image prune -af` — the
# checker has no long-running container holding it (it's spawned per tick), so
# an aggressive prune deletes it and every A&D check then fails to pull it
# (InternalError). The prune cron excludes label org.gzctf.keep=true.
LABEL org.gzctf.keep="true"

COPY check.py /check.py
RUN chmod +x /check.py

# enochecker3 exit-code contract: 0=Ok, 1=Mumble, 2=Offline, 3=InternalError.
# Reads GZCTF_TARGET_IP / GZCTF_TARGET_PORT / GZCTF_ROUND / GZCTF_TEAM_ID.
ENTRYPOINT ["python3", "/check.py"]

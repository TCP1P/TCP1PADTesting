# Minimal static-flag web service. Runs as one container PER TEAM (the default;
# challenge.yml does not set enableSharedContainer).
FROM python:3.12-alpine

WORKDIR /srv
COPY app.py /srv/app.py

EXPOSE 8080
CMD ["python", "/srv/app.py"]

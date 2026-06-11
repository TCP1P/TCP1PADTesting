# Minimal static-flag web service. Runs as a SINGLE shared container for all
# teams (see challenge.yml: container.enableSharedContainer: true).
FROM python:3.12-alpine

WORKDIR /srv
COPY app.py /srv/app.py

EXPOSE 8080
CMD ["python", "/srv/app.py"]

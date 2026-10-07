# DKIM audit service - pure standard library, no build-time network access.
FROM python:3.11-slim

# Application layout inside the image
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DKIM_LISTEN_HOST=0.0.0.0 \
    DKIM_LISTEN_PORT=8080 \
    DKIM_KEYRING=/etc/dkim/keyring.json

WORKDIR /srv/dkim

# Application + tests + smoke tooling live in the image so the one-shot
# verify service can run them against the live API.
COPY app/ ./app/
COPY tests/ ./tests/
COPY smoke/ ./smoke/
COPY verify/entrypoint.sh ./verify/entrypoint.sh
COPY config/keyring.json /etc/dkim/keyring.json

RUN chmod +x /srv/dkim/verify/entrypoint.sh \
    && chown -R nobody:nogroup /srv/dkim

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python3 -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('DKIM_LISTEN_PORT','8080'), timeout=2).status==200 else 1)" || exit 1

USER nobody

ENTRYPOINT ["python3", "app/server.py"]

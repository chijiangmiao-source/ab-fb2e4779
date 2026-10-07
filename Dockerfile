FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    DATA_DIR=/data

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY verify ./verify

RUN useradd --system --uid 10001 station \
    && mkdir -p /data \
    && chown -R station:station /data
USER station

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
  CMD python -c "import urllib.request,sys,os;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/healthz',timeout=2).status==200 else 1)"

CMD ["python", "-m", "app.server"]

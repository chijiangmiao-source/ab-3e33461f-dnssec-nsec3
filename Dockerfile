# 仅使用 Python 3.11 标准库，离线构建无需任何第三方包
FROM python:3.11-slim

WORKDIR /srv

COPY app/ ./app/
COPY tests/ ./tests/
COPY verify_pkg/ ./verify_pkg/
COPY verify /usr/local/bin/verify

RUN chmod +x /usr/local/bin/verify \
    && python3 -m compileall -q app verify_pkg

ENV AUDIT_BIND=0.0.0.0 \
    AUDIT_PORT=8080 \
    AUDIT_DATA_DIR=/data

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=20 \
  CMD ["python3", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

CMD ["python3", "-m", "app.server"]

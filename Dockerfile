# NST web image: API plus the bundled web console.
#
# Put the console in place before building (CI does this):
#   ./scripts/fetch_frontend.sh --release
#   docker build -t nst .
#
# Default: the public demo, listening on 0.0.0.0:8766 for a reverse proxy on
# a Docker network (Coolify's Traefik).  The private console runs the same
# image on the host network, on loopback, with capture capabilities (see
# deploy/console/docker-compose.yml).

ARG PYTHON_VERSION=3.12

# ── Build: wheel from source ─────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build==1.2.2
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="network-security-toolkit" \
      org.opencontainers.image.description="NST web backend (public demo / private console)" \
      org.opencontainers.image.source="https://github.com/khikmat64168-cyber/network-security-toolkit" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# libpcap: BPF filters are compiled with pcap_compile (no shell, no tcpdump).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/nst --shell /usr/sbin/nologin nst \
 && mkdir -p /var/lib/nst /etc/nst \
 && chown nst:nst /var/lib/nst

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[web]" && rm -f /tmp/*.whl

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    XDG_STATE_HOME=/var/lib \
    XDG_CONFIG_HOME=/etc \
    NST_WEB_MODE=public \
    NST_WEB_HOST=0.0.0.0 \
    NST_WEB_PORT=8766 \
    NST_TRUSTED_PROXIES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 ::1/128"

WORKDIR /var/lib/nst
USER nst

EXPOSE 8766

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/mode' % os.environ['NST_WEB_PORT'], timeout=4)" || exit 1

ENTRYPOINT ["nst", "web", "--no-browser"]

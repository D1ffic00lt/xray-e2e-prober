# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The tag documents the interpreter version; the index digest prevents a
# silently replaced base image while still selecting the native architecture.
ARG PYTHON_IMAGE=python:3.13.12-slim-bookworm@sha256:a58daefb915e1e03ad48f3ca4df8832065412c5c35cacb9d39f4229184de12b6

FROM ${PYTHON_IMAGE} AS xray-fetch

ARG TARGETARCH
ARG XRAY_VERSION=26.3.27
ARG XRAY_SHA256_AMD64=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
ARG XRAY_SHA256_ARM64=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) archive="Xray-linux-64.zip"; expected="${XRAY_SHA256_AMD64}" ;; \
      arm64) archive="Xray-linux-arm64-v8a.zip"; expected="${XRAY_SHA256_ARM64}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --show-error --location --proto '=https' --tlsv1.2 \
      --output /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${archive}"; \
    echo "${expected}  /tmp/xray.zip" | sha256sum --check --strict; \
    mkdir -p /tmp/xray /out/bin /out/share/xray; \
    unzip -q /tmp/xray.zip -d /tmp/xray; \
    install -m 0755 /tmp/xray/xray /out/bin/xray; \
    install -m 0644 /tmp/xray/geoip.dat /tmp/xray/geosite.dat /out/share/xray/; \
    /out/bin/xray version | grep -F "Xray ${XRAY_VERSION}"

FROM ${PYTHON_IMAGE} AS python-build

ARG UV_VERSION=0.12.5
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

RUN python -m pip install --disable-pip-version-check --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python-build AS integration-test

ENV PATH=/opt/venv/bin:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XRAY_BINARY=/usr/local/bin/xray \
    XRAY_EXPECTED_VERSION=26.3.27 \
    XRAY_INTEGRATION=1 \
    XRAY_LOCATION_ASSET=/usr/local/share/xray

COPY --from=xray-fetch /out/bin/xray /usr/local/bin/xray
COPY --from=xray-fetch /out/share/xray /usr/local/share/xray
COPY tests ./tests
RUN uv sync --locked --all-groups --no-editable

CMD ["pytest", "-m", "integration", "-q"]

FROM ${PYTHON_IMAGE} AS runtime

ARG APP_VERSION=0.1.0
ARG XRAY_VERSION=26.3.27

LABEL org.opencontainers.image.title="xray-e2e-prober" \
      org.opencontainers.image.description="End-to-end probes through Xray Core" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.xray.version="${XRAY_VERSION}"

ENV PATH=/opt/venv/bin:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROBER_DATA_DIR=/data \
    PROBER_CONFIG=/data/config.yaml \
    PROBER_RUNTIME_DIR=/tmp/xray-e2e-prober \
    XRAY_BINARY=/usr/local/bin/xray \
    XRAY_LOCATION_ASSET=/usr/local/share/xray \
    NO_PROXY=127.0.0.1,localhost

COPY --from=python-build /opt/venv /opt/venv
COPY --from=xray-fetch /out/bin/xray /usr/local/bin/xray
COPY --from=xray-fetch /out/share/xray /usr/local/share/xray

RUN groupadd --gid 10001 prober \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin prober \
    && install -d -o 10001 -g 10001 -m 0700 /data \
    && install -d -o 10001 -g 10001 -m 0700 /tmp/xray-e2e-prober

WORKDIR /app
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=2).read()"]

ENTRYPOINT ["/opt/venv/bin/prober"]
CMD ["serve"]

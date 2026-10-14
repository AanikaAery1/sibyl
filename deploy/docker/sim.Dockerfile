# syntax=docker/dockerfile:1.7
# sibyl-sim: dev-only simulator and chaos control on its own port (R32, R46). Never shipped.
# Build context: repository root (compose: context ../.., dockerfile deploy/docker/sim.Dockerfile).
#
# TLS: networks that re-sign TLS pass their CA as the OPTIONAL BuildKit secret `extra_ca`
# (compose: SIBYL_EXTRA_CA_FILE). It is joined with the system bundle on a tmpfs for the
# download steps only: it never lands in a layer, and verification is never disabled.

# Pinned by multi-arch index digest (L10); bump tag and digest together.
ARG PYTHON_IMAGE=python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS builder
COPY --from=uv /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src

# 1. Third-party dependencies only, cached on the lockfile and the member manifests.
COPY pyproject.toml uv.lock ./
COPY packages/sibyl-schemas/pyproject.toml packages/sibyl-schemas/
COPY packages/sibyl-sdk/pyproject.toml packages/sibyl-sdk/
COPY packages/sibyl-mcp/pyproject.toml packages/sibyl-mcp/
COPY services/control/pyproject.toml services/control/
COPY services/gateway/pyproject.toml services/gateway/
COPY sibyl-sim/pyproject.toml sibyl-sim/
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=extra_ca,required=false \
    --mount=type=tmpfs,target=/run/ca \
    set -eu; \
    bundle=/etc/ssl/certs/ca-certificates.crt; \
    if [ -s /run/secrets/extra_ca ]; then \
      cat "$bundle" /run/secrets/extra_ca > /run/ca/bundle.pem; bundle=/run/ca/bundle.pem; \
    fi; \
    SSL_CERT_FILE="$bundle" uv sync --frozen --no-dev --no-install-workspace --package sibyl-sim

# 2. This image's workspace sources only, installed non-editable.
COPY packages/sibyl-schemas packages/sibyl-schemas
COPY packages/sibyl-sdk packages/sibyl-sdk
COPY sibyl-sim sibyl-sim
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=extra_ca,required=false \
    --mount=type=tmpfs,target=/run/ca \
    set -eu; \
    bundle=/etc/ssl/certs/ca-certificates.crt; \
    if [ -s /run/secrets/extra_ca ]; then \
      cat "$bundle" /run/secrets/extra_ca > /run/ca/bundle.pem; bundle=/run/ca/bundle.pem; \
    fi; \
    SSL_CERT_FILE="$bundle" uv sync --frozen --no-dev --no-editable --package sibyl-sim

FROM ${PYTHON_IMAGE} AS runtime
ARG SIBYL_VERSION=dev
LABEL org.opencontainers.image.title="sibyl-sim" \
      org.opencontainers.image.version="${SIBYL_VERSION}" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
RUN groupadd --system --gid 10001 sibyl \
 && useradd --system --uid 10001 --gid sibyl --no-create-home --shell /usr/sbin/nologin sibyl
# Exports the compose secrets granted to this service (/run/secrets/SIBYL_*) as env vars.
COPY --chmod=0555 deploy/docker/sibyl-entrypoint.sh /usr/local/bin/sibyl-entrypoint
COPY --from=builder /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIBYL_VERSION=${SIBYL_VERSION}
WORKDIR /app
USER sibyl:sibyl
ENTRYPOINT ["/usr/local/bin/sibyl-entrypoint"]
EXPOSE 8300
CMD ["python", "-m", "sibyl_sim", "serve", "--host", "0.0.0.0", "--port", "8300"]

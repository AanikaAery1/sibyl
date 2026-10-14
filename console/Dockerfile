# syntax=docker/dockerfile:1.7
# Sibyl console: Next.js standalone server (BFF + UI), demo-data mode by default.
# Build context: console/ (compose: context ../../console, dockerfile Dockerfile).
#
# TLS: networks that re-sign TLS pass their CA as the OPTIONAL BuildKit secret `extra_ca`
# (compose: SIBYL_EXTRA_CA_FILE). It is used for `npm ci` only, never lands in a layer, and
# verification is never disabled.

ARG NODE_IMAGE=node:22.20.0-alpine3.22

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=secret,id=extra_ca,required=false \
    set -eu; \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npm ci --no-audit --no-fund --ignore-scripts

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx next build

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    SIBYL_CONSOLE_MODE=demo
RUN addgroup -S sibyl && adduser -S -G sibyl -u 10001 sibyl
COPY --from=build --chown=sibyl:sibyl /app/.next/standalone ./
COPY --from=build --chown=sibyl:sibyl /app/.next/static ./.next/static
USER sibyl
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "server.js"]

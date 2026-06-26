# syntax=docker/dockerfile:1

# ─── Stage 1: build ──────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# Install git (needed by `go mod download` for private modules if any).
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependency downloads as a separate layer so they are only re-fetched
# when go.mod / go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source tree and compile a statically linked binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/ztfp ./cmd/proxy

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM scratch

# Pull in TLS root certificates and timezone data from the builder stage so
# the proxy can verify upstream TLS chains without a full OS layer.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the compiled binary.
COPY --from=builder /out/ztfp /ztfp

# Copy HTML templates required at runtime by the block-page renderer.
COPY html_templates/ /html_templates/

# Proxy traffic port and Prometheus metrics port.
EXPOSE 8080 9090

# Run as non-root UID to satisfy PodSecurityAdmission restricted policy.
USER 65534:65534

ENTRYPOINT ["/ztfp"]
# Default flag; override with env vars (ZTFP_*) or a custom --config mount.
CMD ["--config", "/etc/ztfp/config.yaml"]

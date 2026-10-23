# kameas-relay — production image for cmd/relayd.
#
# Distroless static final stage, non-root, no shell. The relay's only
# cryptographic surface is TLS (Go stdlib) and JWT/JWKS validation
# (relay-api.md §1), so the image needs CA certificates and nothing else:
# no package manager, no busybox, no libsodium, nothing that could grow one.
#
# Every FROM is pinned by multi-arch index digest (security baseline 2026-10-22,
# WS1 / CVE-2026-111943); the tag is kept for readability. Digests resolved
# 2026-10-22 (golang via docker-library/repo-info, distroless from gcr.io).
# Bump tag + digest together; Dependabot's docker ecosystem keeps both current.

# ---- build ----------------------------------------------------------------
# golang:1.27-bookworm == golang:1.27.3-bookworm at this digest (go1.27.3 carries
# the CVE-2026-111943 crypto/x509 eMudhra denylist; go.mod pins toolchain go1.27.3).
FROM golang:1.27-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build

WORKDIR /src

# Dependencies first so the module layer caches independently of source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/relayd ./cmd/relayd

# ---- final ----------------------------------------------------------------
# static-debian12 bundles Debian's ca-certificates (20250419~deb12u1 at this
# digest, resolved 2026-10-22; the image's created date is the epoch, so the
# package version is the freshness marker). Re-pin when Debian ships the Mozilla
# eMudhra distrust; Go's own x509 denylist already covers relayd.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

LABEL org.opencontainers.image.title="kameas-relay"
LABEL org.opencontainers.image.description="Ciphertext rendezvous for Kenaz iOS Remote (spec 074). Cannot decrypt what it forwards."
LABEL org.opencontainers.image.source="https://github.com/kameas-ai/kameas-relay"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/relayd /usr/local/bin/relayd

# distroless:nonroot is uid/gid 65532. Stated explicitly so a base-image
# change cannot silently promote the process to root.
USER 65532:65532

ENV RELAY_ADDR=:8080
EXPOSE 8080

# relayd serves its own liveness probe (relay-api.md §7.3: unauthenticated,
# no operator data, no enumeration). There is no shell and no curl in the
# final image, so the probe is the binary itself.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/relayd", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/relayd"]

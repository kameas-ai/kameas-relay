# kameas-relay — production image for cmd/relayd.
#
# Distroless static final stage, non-root, no shell. The relay's only
# cryptographic surface is TLS (Go stdlib) and JWT/JWKS validation
# (relay-api.md §1), so the image needs CA certificates and nothing else:
# no package manager, no busybox, no libsodium, nothing that could grow one.

# ---- build ----------------------------------------------------------------
FROM golang:1.25-bookworm AS build

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
FROM gcr.io/distroless/static-debian12:nonroot

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

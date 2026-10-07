# syntax=docker/dockerfile:1

# Build stage: compile the API server and the smoke verifier, and make sure
# the unit tests pass before any runtime image can be produced.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY scripts ./scripts
RUN go test ./... \
 && go build -o /out/server ./cmd/server \
 && go build -o /out/verify ./cmd/verify

# API runtime image.
FROM alpine:3.20 AS api
RUN adduser -D -u 10001 app
COPY --from=build /out/server /usr/local/bin/server
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]

# One-shot verify image: keeps the Go toolchain and the source tree so the
# entrypoint can run the code tests and build before the HTTP smoke suite.
FROM golang:1.27-bookworm AS verify
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY scripts ./scripts
COPY --from=build /out/verify /usr/local/bin/verify
COPY fixtures /fixtures
RUN chmod +x /src/scripts/verify-entry.sh \
 && cp /src/scripts/verify-entry.sh /usr/local/bin/verify-entry
ENV API_URL=http://api:8080 \
    FIXTURES_DIR=/fixtures
ENTRYPOINT ["/usr/local/bin/verify-entry"]

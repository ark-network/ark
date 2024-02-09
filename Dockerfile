# First image used to build the sources
FROM golang:1.21.0 AS builder

ARG VERSION
ARG COMMIT
ARG DATE
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN cd asp && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${COMMIT}' -X 'main.Commit=${COMMIT}' -X 'main.Date=${COMMIT}'" -o ../bin/arkd cmd/arkd/main.go

# Second image, running the arkd executable
FROM debian:buster-slim

WORKDIR /app

COPY --from=builder /app/bin/* /app

ENV PATH="/app:${PATH}"
ENV ARK_DATADIR=/app/data

# Expose volume containing all 'arkd' data
VOLUME /app/data

ENTRYPOINT [ "arkd" ]
    
FROM golang:1.21.0 AS builder
ARG VERSION
ARG COMMIT
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY . .
ENV GOPROXY=https://goproxy.io,direct

RUN BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
    cd server && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}'" \
    -o ../bin/arkd ./cmd/arkd

RUN BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
    cd client && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}'" \
    -o ../bin/ark .


# Second image, running the arkd executable
FROM alpine:3.12

WORKDIR /app

COPY --from=builder /app/bin/* /app/
COPY --from=builder /app/server/internal/infrastructure/db/sqlite/migration/* /app/

ENV PATH="/app:${PATH}"
ENV ARK_DATADIR=/app/data
ENV ARK_WALLET_DATADIR=/app/wallet-data
ENV ARK_DB_MIGRATION_PATH=file://

# Expose volume containing all 'arkd' data
VOLUME /app/data
VOLUME /app/wallet-data

ENTRYPOINT [ "arkd" ]
    

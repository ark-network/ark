# First stage: build the ark-wallet-daemon binary
FROM golang:1.23.1 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o /app/bin/arkd-wallet ./pkg/ark-wallet/cmd/main.go

# Second stage: minimal runtime image
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/arkd-wallet /app/

ENV PATH="/app:${PATH}"
ENV ARK_WALLET_DATADIR=/app/wallet-data

VOLUME /app/wallet-data

ENTRYPOINT [ "arkd-wallet" ]

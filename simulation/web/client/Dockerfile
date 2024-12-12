FROM golang:1.23.1 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy the go.mod and go.sum files from ./simulation
COPY simulation/go.mod simulation/go.sum ./

# Copy the go.work file from the root
COPY go.work ./

# Set GOWORK to use the workspace file
ENV GOWORK=/app/go.work

# Copy necessary directories
COPY common/ ./common/
COPY pkg/ ./pkg/
COPY api-spec ./api-spec/
COPY client ./client/
COPY server ./server/
COPY server/pkg/kvdb ./server/pkg/kvdb/
COPY server/pkg/macaroons ./server/pkg/macaroons/
COPY simulation ./simulation/

# Copy the main.go file from ./simulation/web/client
COPY simulation/web/client/main.go ./

RUN go mod download

# Build the binary with explicit name
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -v -ldflags="-X 'main.Version=${VERSION}'" -o arkclient main.go

# Stage 2: Create the runtime image
FROM alpine:latest

# Install necessary packages, including CA certificates
RUN apk add --no-cache file ca-certificates

# Copy the binary with a specific name
COPY --from=builder /app/arkclient /arkclient

# Verify the binary
RUN ls -la . && \
    chmod +x /arkclient && \
    file /arkclient

EXPOSE 9000

# Use the binary as entrypoint
ENTRYPOINT ["./arkclient"]

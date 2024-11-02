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


# Copy the main.go file from ./simulation/remote/client
COPY simulation/remote/client/main.go ./

RUN go mod download

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-X 'main.Version=${VERSION}'" -o client main.go

# Stage 2: Create the runtime image
FROM alpine:latest

WORKDIR /root/
COPY --from=builder /app/client .

ENTRYPOINT ["./client"]

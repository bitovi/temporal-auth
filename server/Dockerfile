# Build Stage: Use latest Go version
FROM golang:1.24.5 AS builder

WORKDIR /app

# Install GCC and required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libc-dev \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -u 1000 -m temporaluser

# Set up permissions for Go modules cache (to avoid permission denied issues)
RUN mkdir -p /go/pkg/mod /go/build && \
    chown -R temporaluser:temporaluser /go/pkg /go/build /app && \
    chmod -R 777 /go/pkg /go/build /app

# Install gomplate (multi-arch: amd64/arm64)
ARG GOMPLATE_VERSION=v3.11.5
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN set -eux; \
    echo "Installing gomplate ${GOMPLATE_VERSION} for ${TARGETOS:-linux}-${TARGETARCH}"; \
    case "${TARGETARCH}" in amd64|arm64) ;; *) echo "Unsupported arch: ${TARGETARCH}"; exit 1;; esac; \
    curl -fsSL -o /usr/local/bin/gomplate "https://github.com/hairyhenderson/gomplate/releases/download/${GOMPLATE_VERSION}/gomplate_${TARGETOS:-linux}-${TARGETARCH}"; \
    chmod +x /usr/local/bin/gomplate; \
    /usr/local/bin/gomplate -v

# Set environment variables for CGO to work
ENV CGO_ENABLED=1
ENV CC=gcc
ENV CXX=g++
ENV GOPATH=/go
ENV GOCACHE=/go/build

# Copy Go module files first (better Docker caching)
COPY go.mod go.sum ./

# Download dependencies as root (better caching)
RUN go mod download

# Switch to non-root user
USER temporaluser

# Copy the source code after dependencies are downloaded
COPY --chown=temporaluser:temporaluser . .

# Build the Go binary
RUN go build -o /app/temporal-auth-server main.go

# Ensure  execute permissions
RUN chmod +x /app/temporal-auth-server
RUN chmod +x /app/startup.sh
RUN mkdir -p /app/config

# Set back to root for final runtime setup
USER root

# Use the start script as entrypoint
ENTRYPOINT ["/app/startup.sh"]
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

ENV DOCKERIZE_VERSION v0.9.0

RUN apt-get update \
    && apt-get install -y wget \
    && wget -O - https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-arm64-$DOCKERIZE_VERSION.tar.gz | tar xzf - -C /usr/local/bin \
    && apt-get autoremove -yqq --purge wget && rm -rf /var/lib/apt/lists/*

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

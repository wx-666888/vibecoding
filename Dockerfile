# syntax=docker/dockerfile:1

# Stage 1: Build binaries
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Create non-root user file for scratch stages
RUN echo "appuser:x:65532:65532:appuser:/app:/bin/false" > /etc/passwd_app

# Copy dependency definition
COPY go.mod ./
RUN go mod download

# Copy source code and rules
COPY . .

# Build statically linked server and client
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -extldflags '-static'" -o /out/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -extldflags '-static'" -o /out/client ./cmd/client

# Stage 2: Server runtime
FROM scratch AS server

COPY --from=builder /etc/passwd_app /etc/passwd
COPY --from=builder /out/server /app/server
COPY --from=builder /src/rules/rules.json /app/rules/rules.json

USER 65532:65532
WORKDIR /app
EXPOSE 8080

ENTRYPOINT ["/app/server"]

# Stage 3: Client runtime
FROM scratch AS client

COPY --from=builder /etc/passwd_app /etc/passwd
COPY --from=builder /out/client /app/client

USER 65532:65532
WORKDIR /app

ENTRYPOINT ["/app/client"]

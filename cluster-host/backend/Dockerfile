FROM golang:1.24-alpine AS builder
WORKDIR /app

# Build cluster-target agent binary for ALL supported platforms
COPY cluster-target/go.mod cluster-target/go.sum ./cluster-target/
RUN cd cluster-target && go mod download
COPY cluster-target ./cluster-target
RUN mkdir -p /app/agent_assets && cd cluster-target && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o /app/agent_assets/cluster-target-linux-amd64   . && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o /app/agent_assets/cluster-target-linux-arm64   . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -o /app/agent_assets/cluster-target-darwin-amd64  . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o /app/agent_assets/cluster-target-darwin-arm64  . && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /app/agent_assets/cluster-target-windows-amd64.exe .
COPY cluster-target/cluster-target.service /app/agent_assets/cluster-target.service

# Build host backend binary
COPY cluster-host/backend/go.mod cluster-host/backend/go.sum ./cluster-host/backend/
RUN cd cluster-host/backend && go mod download
COPY cluster-host/backend ./cluster-host/backend
RUN cd cluster-host/backend && CGO_ENABLED=0 GOOS=linux go build -o /app/backend .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/backend /app/backend
COPY --from=builder /app/agent_assets /app/agent_assets
EXPOSE 5000
CMD ["./backend"]

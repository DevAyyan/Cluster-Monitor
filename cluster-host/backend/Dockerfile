FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o backend .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/backend /app/backend
COPY --from=builder /app/agent_assets /app/agent_assets
EXPOSE 5000
CMD ["./backend"]

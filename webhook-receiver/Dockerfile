FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o webhook .

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/webhook .
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["./webhook"]

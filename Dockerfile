FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /qs ./cmd/qs/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /qsserver ./cmd/qsserver/

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /qs /usr/local/bin/qs
COPY --from=builder /qsserver /usr/local/bin/qsserver
COPY --from=builder /app/testdata /app/testdata

WORKDIR /app

EXPOSE 8080

ENV PORT=8080
ENV QS_WATCH_PATH=/app/testdata

CMD ["qsserver"]

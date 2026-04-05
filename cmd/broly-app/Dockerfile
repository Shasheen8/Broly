FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o broly-app ./cmd/broly-app


FROM cgr.dev/chainguard/git:latest

COPY --from=builder /build/broly-app /usr/local/bin/broly-app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/broly-app"]

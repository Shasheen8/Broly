FROM cgr.dev/chainguard/python:latest-dev AS zizmor

USER root
RUN pip install --no-cache-dir --prefix=/opt/zizmor 'zizmor==1.26.1' \
    && /opt/zizmor/bin/zizmor --version

FROM cgr.dev/chainguard/python:latest-dev AS checkov

USER root
RUN python -m venv --copies /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir 'checkov==3.3.8' \
    && /opt/checkov/bin/checkov --version

FROM cgr.dev/chainguard/go:latest AS depx

ARG DEPX_VERSION=0.1.1
ADD https://github.com/projectdiscovery/depx/archive/refs/tags/v${DEPX_VERSION}.tar.gz /tmp/depx.tar.gz
RUN mkdir -p /src && tar -xzf /tmp/depx.tar.gz -C /src
WORKDIR /src/depx-${DEPX_VERSION}
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /go/bin/depx ./cmd/depx
RUN mkdir -p /depx-home/.cache \
    && (HOME=/depx-home /go/bin/depx search malicious-css-exfil --json --silent | grep -q '"packages"' \
        && echo "depx index warmed" || echo "WARN: depx index unavailable at build; shipping without warm cache")

FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o broly-app ./cmd/broly-app

FROM cgr.dev/chainguard/git:latest

COPY --from=zizmor /opt/zizmor/bin/zizmor /usr/local/bin/zizmor
COPY --from=checkov /opt/checkov /opt/checkov
COPY --from=checkov /usr/bin/python3.14 /usr/bin/python3.14
COPY --from=checkov /usr/bin/python3 /usr/bin/python3
COPY --from=checkov /usr/bin/python /usr/bin/python
COPY --from=checkov /usr/lib/libpython3.14.so.1.0 /usr/lib/libpython3.14.so.1.0
COPY --from=checkov /usr/lib/libffi.so.8 /usr/lib/libffi.so.8
COPY --from=checkov /usr/lib/liblzma.so.5 /usr/lib/liblzma.so.5
COPY --from=checkov /usr/lib/python3.14 /usr/lib/python3.14
COPY --from=depx /go/bin/depx /usr/local/bin/depx
COPY --from=depx --chmod=0777 /depx-home/.cache /opt/depx-home/.cache
ENV DEPX_HOME=/opt/depx-home
COPY --from=builder /build/broly-app /usr/local/bin/broly-app

ENV PATH="/opt/checkov/bin:${PATH}"
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/broly-app"]
# syntax=docker/dockerfile:1

FROM golang:1.23-bookworm AS build

WORKDIR /src

# Download dependencies in separate layers so source-only changes build quickly.
COPY general-simulation/go.mod general-simulation/go.sum ./general-simulation/
COPY malicious-proxy-simulation/go.mod malicious-proxy-simulation/go.sum ./malicious-proxy-simulation/
COPY real-world/snowflake/go.mod real-world/snowflake/go.sum ./real-world/snowflake/

RUN --mount=type=cache,target=/go/pkg/mod \
    cd general-simulation && go mod download
RUN --mount=type=cache,target=/go/pkg/mod \
    cd malicious-proxy-simulation && go mod download
RUN --mount=type=cache,target=/go/pkg/mod \
    cd real-world/snowflake && go mod download

COPY general-simulation ./general-simulation
COPY malicious-proxy-simulation ./malicious-proxy-simulation
COPY real-world/snowflake ./real-world/snowflake

RUN mkdir /out
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd general-simulation && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/general-simulation ./broker
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd malicious-proxy-simulation && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/malicious-proxy-simulation ./broker
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd real-world/snowflake && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/real-world-prober ./client/prober.go

FROM debian:bookworm-slim

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /usr/local/bin/
COPY --from=build /src/general-simulation/broker/run_enumeration.sh \
                  /src/general-simulation/broker/run_blocking.sh \
                  /opt/general-simulation/broker/
COPY --from=build /src/malicious-proxy-simulation/broker/run_malicious.sh \
                  /opt/malicious-proxy-simulation/broker/

# Each Compose service writes its results to a separate named volume here.
RUN chmod +x /opt/general-simulation/broker/run_enumeration.sh \
             /opt/general-simulation/broker/run_blocking.sh \
             /opt/malicious-proxy-simulation/broker/run_malicious.sh && \
    mkdir /output && chown 65532:65532 /output

ENV SIMULATOR_BIN=/usr/local/bin/general-simulation \
    OUT_ROOT=/output

USER 65532:65532
WORKDIR /opt/general-simulation/broker

# Run both default general-simulation experiments in sequence.
CMD ["/bin/bash", "-c", "ONLY_REGEX='default' ./run_enumeration.sh && ONLY_REGEX='default' ./run_blocking.sh"]

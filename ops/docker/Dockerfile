# Reproducible-ish build of the Enclave server and relay.
# docker build -f ops/docker/Dockerfile -t enclave-server .
FROM rust:1.94.1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p enclave-server -p enclave-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/enclave-server /usr/local/bin/enclave-server
COPY --from=build /src/target/release/enclave-relay /usr/local/bin/enclave-relay
USER nonroot
# Dev transport only. Production servers are reached through their Nym
# client (docs/12-servers.md); do not publish this port on the internet.
EXPOSE 7443
ENTRYPOINT ["/usr/local/bin/enclave-server", "0.0.0.0:7443"]

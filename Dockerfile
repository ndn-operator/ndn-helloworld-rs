FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bins

FROM debian:bookworm-slim
COPY --from=build /src/target/release/producer /producer
COPY --from=build /src/target/release/consumer /consumer
USER 65532:65532
ENTRYPOINT ["/consumer"]

FROM clux/muslrust:stable AS build
ARG TARGET
ARG VERSION
WORKDIR /src
COPY . .
RUN cargo install cargo-edit
RUN cargo set-version "${VERSION}"
RUN cargo build --target=${TARGET} --release --locked --bins

FROM scratch
ARG TARGET
COPY --from=build /src/target/${TARGET}/release/producer /producer
COPY --from=build /src/target/${TARGET}/release/consumer /consumer
USER 65532:65532
ENTRYPOINT ["/consumer"]

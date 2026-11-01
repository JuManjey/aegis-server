# AEGIS relay — многоступенчатая сборка (§12.2).
# Этап 1: сборка статически-достаточного бинаря (SQLite bundled — без системной libsqlite3).
#
# Reproducible builds (P9, §9/§12.1): базовый образ пинуется ТОЧНОЙ версией Rust
# (совпадает с rust-toolchain.toml). Для максимальной воспроизводимости пинуйте
# образ по digest, например:
#   FROM rust:1.97.0-bookworm@sha256:<digest> AS build
# (digest фиксирует и версию Debian, и патчи). См. docs/reproducible-builds.md.
FROM rust:1.97.0-bookworm AS build
# CARGO_INCREMENTAL=0 — инкрементальная компиляция недетерминирована и не нужна в CI.
# SOURCE_DATE_EPOCH можно пробросить через build-arg для детерминизма метаданных.
ENV CARGO_INCREMENTAL=0
WORKDIR /src
# Кэш зависимостей: сначала манифесты, затем исходники.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
# --locked — сборка строго по Cargo.lock (запрещает молчаливое обновление версий).
RUN cargo build --release --locked && strip target/release/aegis-relay

# Этап 2: минимальный runtime.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /home/aegis aegis \
    && mkdir -p /data && chown aegis:aegis /data
COPY --from=build /src/target/release/aegis-relay /usr/local/bin/aegis-relay
USER aegis
# Внутри compose-сети слушаем все интерфейсы, но НАРУЖУ порт не публикуется —
# доступ только через tor-контейнер (Onion Service v3).
ENV AEGIS_BIND=0.0.0.0:8080 \
    AEGIS_DB=/data/aegis-relay.db
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/v1/health || exit 1
CMD ["aegis-relay"]

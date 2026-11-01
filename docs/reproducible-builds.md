# AEGIS relay — воспроизводимые сборки

> P9 (§9/§12.1). Сервер собирается детерминированно, чтобы деплой можно было
> сверить с открытым кодом. Полная концепция — в клиентском
> `aegis-client/docs/reproducible-builds.md`; здесь — специфика backend.

## Инварианты

| Слой | Механизм | Файл |
|------|----------|------|
| Rust-тулчейн | точная версия `1.97.0` | `rust-toolchain.toml` |
| Docker base | `rust:1.97.0-bookworm` (реком. пин по digest) | `Dockerfile` |
| Крейты | `Cargo.lock` + сборка `--locked` | `Cargo.lock`, `Dockerfile` |
| Пути в бинаре | `--remap-path-prefix` (RUSTFLAGS) | `scripts/verify-reproducible-build.sh` |
| Release-профиль | `opt-level=3, lto, codegen-units=1, strip` | `Cargo.toml` |
| Детерминизм | `CARGO_INCREMENTAL=0`, `TZ=UTC`, `LC_ALL=C`, `SOURCE_DATE_EPOCH` | скрипт / Dockerfile |

Версия Rust (`1.97.0`) едина с клиентским ядром.

## Проверка

```bash
# Локальная двойная сборка + сравнение SHA-256:
scripts/verify-reproducible-build.sh

# + сборка в Docker (rust:1.97.0-bookworm) и хэш бинаря:
AEGIS_VERIFY_DOCKER=1 scripts/verify-reproducible-build.sh
```

## Пин Docker-образа по digest (сильнее)

```dockerfile
FROM rust:1.97.0-bookworm@sha256:<digest> AS build
```

Digest фиксирует и версию Debian, и патч-уровень. Получить:

```bash
docker pull rust:1.97.0-bookworm
docker inspect --format='{{index .RepoDigests 0}}' rust:1.97.0-bookworm
```

## SBOM

```bash
scripts/generate-sbom.sh   # → docs/sbom/
```

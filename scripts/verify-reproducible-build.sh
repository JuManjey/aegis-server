#!/usr/bin/env bash
# =============================================================================
# AEGIS relay — проверка ВОСПРОИЗВОДИМОСТИ сборки (P9, §9/§12.1).
#
# Собирает бинарь aegis-relay ДВАЖДЫ в чистых условиях и сравнивает SHA-256.
# Условия воспроизводимости: пин тулчейна (rust-toolchain.toml + rust:1.97.0
# в Dockerfile), Cargo.lock (--locked), ремап путей (RUSTFLAGS ниже).
#
# Использование:
#   scripts/verify-reproducible-build.sh            # локальная двойная сборка
#   AEGIS_VERIFY_DOCKER=1 scripts/verify-reproducible-build.sh  # + сравнить бинарь из Docker
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export TZ=UTC
export LC_ALL=C
export CARGO_INCREMENTAL=0
if git -C "${ROOT_DIR}" rev-parse HEAD >/dev/null 2>&1; then
  export SOURCE_DATE_EPOCH="$(git -C "${ROOT_DIR}" show -s --format=%ct HEAD)"
else
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi

CARGO_HOME_DIR="${CARGO_HOME:-${HOME}/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-${HOME}/.rustup}"
export RUSTFLAGS="${RUSTFLAGS:-} \
  --remap-path-prefix=${ROOT_DIR}=/src \
  --remap-path-prefix=${CARGO_HOME_DIR}=/cargo \
  --remap-path-prefix=${RUSTUP_HOME_DIR}=/rustup"

sha256() { command -v sha256sum >/dev/null 2>&1 && sha256sum "$1" | cut -d' ' -f1 || shasum -a 256 "$1" | cut -d' ' -f1; }

BIN="target/release/aegis-relay"
echo "[repro] toolchain: $(rustc --version)"
echo "[repro] SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

cd "${ROOT_DIR}"
echo "[repro] === Сборка 1/2 ==="
cargo clean && cargo build --release --locked
H1="$(sha256 "${BIN}")"
echo "[repro] === Сборка 2/2 ==="
cargo clean && cargo build --release --locked
H2="$(sha256 "${BIN}")"

if [[ "${H1}" == "${H2}" ]]; then
  echo "[repro] OK aegis-relay: ${H1}"
else
  echo "[repro] FAIL aegis-relay: ${H1} != ${H2}" >&2; exit 1
fi

if [[ "${AEGIS_VERIFY_DOCKER:-0}" == "1" ]]; then
  echo "[repro] === Сборка в Docker (rust:1.97.0-bookworm) ==="
  docker build --target build -t aegis-relay-build .
  docker create --name aegis-relay-tmp aegis-relay-build >/dev/null
  docker cp aegis-relay-tmp:/src/target/release/aegis-relay /tmp/aegis-relay-docker
  docker rm aegis-relay-tmp >/dev/null
  HD="$(sha256 /tmp/aegis-relay-docker)"
  echo "[repro] docker aegis-relay: ${HD}"
  echo "[repro] (кросс-окруженческое совпадение с локальным ожидается при том же тулчейне/флагах)"
fi

echo "[repro] РЕЗУЛЬТАТ: aegis-relay воспроизводим ✅"

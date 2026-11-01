#!/usr/bin/env bash
# =============================================================================
# AEGIS relay — генерация SBOM / инвентаря зависимостей (P9, аудит §9/§1).
# Источник истины по версиям — Cargo.lock. Выход: docs/sbom/.
#   cargo install cargo-license cargo-cyclonedx   # опциональные инструменты
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${ROOT_DIR}/docs/sbom"
mkdir -p "${OUT_DIR}"
cd "${ROOT_DIR}"

echo "[sbom] дерево крейтов → cargo-tree.txt"
cargo tree --edges normal > "${OUT_DIR}/cargo-tree.txt"

if command -v cargo-license >/dev/null 2>&1; then
  echo "[sbom] лицензии крейтов → cargo-licenses.txt"
  cargo license > "${OUT_DIR}/cargo-licenses.txt" || true
else
  echo "[sbom] cargo-license не установлен — пропуск."
fi

if command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "[sbom] CycloneDX → cargo-sbom.cdx.json"
  cargo cyclonedx --format json || true
  find . -maxdepth 1 -name '*.cdx.json' -exec mv {} "${OUT_DIR}/cargo-sbom.cdx.json" \; 2>/dev/null || true
else
  echo "[sbom] cargo-cyclonedx не установлен — пропуск."
fi

echo "[sbom] ГОТОВО. Файлы в ${OUT_DIR}/"

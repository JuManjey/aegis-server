# SBOM / инвентарь зависимостей (aegis-relay)

Перечень зависимостей backend для аудита (P9, §9/§1).

| Файл | Что это | Как получить |
|------|---------|--------------|
| `cargo-tree.txt` | дерево крейтов с версиями | `scripts/generate-sbom.sh` |
| `cargo-licenses.txt` | лицензии крейтов | `cargo install cargo-license` затем скрипт |
| `cargo-sbom.cdx.json` | CycloneDX SBOM | `cargo install cargo-cyclonedx` затем скрипт |

Источник истины по версиям — `Cargo.lock`. Обзор лицензий продукта —
`aegis-client/THIRD_PARTY_NOTICES.md`.

## Обновление

```bash
scripts/generate-sbom.sh
git add docs/sbom && git commit -m "docs(sbom): обновить инвентарь зависимостей"
```

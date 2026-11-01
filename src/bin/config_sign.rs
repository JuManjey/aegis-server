//! `aegis-config-sign` — офлайн-инструмент подписи конфиг-документа релея (§12.2).
//!
//! Клиент AEGIS получает адрес(а) onion-релея через `GET /v1/config`, чтобы
//! пользователь НЕ вводил его вручную. Чтобы даже скомпрометированный сервер не
//! мог подменить адрес, документ подписывается офлайн-ключом Ed25519, публичная
//! часть которого зашита в APK (`AEGIS_RELAY_CONFIG_PUBKEY` при сборке клиента).
//!
//! Приватный ключ НИКОГДА не кладётся на сервер — этот инструмент запускается на
//! доверенной офлайн-машине оператора и выводит две строки для `.env` релея.
//!
//! Сборка/запуск (только с фичей `tools`, в прод-образ релея не попадает).
//!
//! Шаг 1 — сгенерировать ключ (один раз). Приватный ХРАНИТЬ ОФЛАЙН, публичный
//! зашить в клиент при сборке APK:
//!
//! `cargo run --features tools --bin aegis-config-sign -- keygen`
//!
//! Шаг 2 — подписать документ с адресами релея (строки AEGIS_CONFIG_DOC/SIG
//! для `.env`):
//!
//! `cargo run --features tools --bin aegis-config-sign -- sign --key <PRIV_HEX>
//! --relay <hs>.onion --relay-https https://<домен> --turn <hs>.onion
//! --turn-port 3478 --version 1 --min-app 2`
//!
//! `--relay` — onion для режима Tor, `--relay-https` — тот же релей по HTTPS для
//! режима без Tor (обязан вести к той же БД). `--https-pin sha256/<base64>` —
//! необязательные пины SPKI к HTTPS-адресу. Новые поля аддитивные: старый клиент
//! их игнорирует.
//!
//! Ротация адреса: увеличить `--version` (клиент отвергает документ со СТАРОЙ
//! версией — защита от отката) и переподписать.

use std::process::exit;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn usage() -> ! {
    eprintln!(
        "aegis-config-sign — офлайн-подпись конфига релея (§12.2)\n\n\
         Команды:\n  \
           keygen                       Сгенерировать пару ключей Ed25519.\n  \
           sign --key <privhex> --relay <onion> [--relay-https <url>] [опции]\n\n\
         Опции sign:\n  \
           --key <hex>          Приватный ключ (32 байта hex) из keygen. ОБЯЗАТЕЛЬНО.\n  \
           --relay <onion>      Адрес onion-релея. Можно повторять (первый — основной).\n  \
           --relay-https <url>  HTTPS-адрес ТОГО ЖЕ релея (https://host[:port]) для режима\n                       \
                                без Tor. Можно повторять. Нужен хотя бы один --relay или --relay-https.\n  \
           --https-pin <pin>    (опц.) Пин SPKI к HTTPS-адресу: sha256/<base64 32 байт>. Повторяемый.\n  \
           --turn <onion>       (опц.) onion-адрес coturn (информативно для клиента).\n  \
           --turn-port <n>      (опц.) TCP-порт coturn на onion (по умолч. 3478).\n  \
           --version <n>        (опц.) Версия документа (по умолч. 1). Растить при ротации.\n  \
           --min-app <n>        (опц.) Минимальный versionCode клиента (по умолч. 0)."
    );
    exit(2);
}

/// Нормализует HTTPS-адрес релея к `https://host[:port]`. `None` — не https,
/// есть путь/query/userinfo или хост некорректный (клиент такой адрес отверг бы).
fn normalize_https(raw: &str) -> Option<String> {
    let rest = raw.trim().strip_prefix("https://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().ok().filter(|p| *p > 0)?)),
        None => (rest, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && !host.ends_with(".onion")
        && host.split('.').all(|l| {
            !l.is_empty() && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid {
        return None;
    }
    Some(match port {
        Some(443) | None => format!("https://{host}"),
        Some(p) => format!("https://{host}:{p}"),
    })
}

/// Нормализует пин SPKI к `sha256/<base64>`; `None`, если это не 32 байта base64.
fn normalize_pin(raw: &str) -> Option<String> {
    let value = raw.trim();
    let value = value.strip_prefix("sha256/").unwrap_or(value);
    let bytes = base64::engine::general_purpose::STANDARD.decode(value).ok()?;
    (bytes.len() == 32).then(|| format!("sha256/{}", b64(&bytes)))
}

/// Каноничный payload документа. Новые поля (`relaysHttps`, `httpsPins`)
/// появляются только если заданы — документ старого формата не меняется.
fn build_payload(
    version: u64,
    relays: &[String],
    relays_https: &[String],
    https_pins: &[String],
    min_app: u64,
    turn: Option<(&str, u16)>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "v": version,
        "relays": relays,
        "minAppVersion": min_app,
    });
    if !relays_https.is_empty() {
        payload["relaysHttps"] = serde_json::json!(relays_https);
    }
    if !https_pins.is_empty() {
        payload["httpsPins"] = serde_json::json!(https_pins);
    }
    if let Some((onion, port)) = turn {
        payload["turnOnion"] = serde_json::Value::String(onion.to_string());
        payload["turnPort"] = serde_json::Value::from(port);
    }
    payload
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("sign") => sign(&args[2..]),
        _ => usage(),
    }
}

fn keygen() {
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let priv_hex = to_hex(signing.to_bytes().as_slice());
    let pub_hex = to_hex(signing.verifying_key().to_bytes().as_slice());
    eprintln!("# Ed25519-ключ подписи конфига релея (§12.2). Сгенерирован офлайн.");
    eprintln!("# ПРИВАТНЫЙ КЛЮЧ — храните строго офлайн, НЕ кладите на сервер и в git:");
    println!("PRIVATE_KEY_HEX={priv_hex}");
    eprintln!("# ПУБЛИЧНЫЙ КЛЮЧ — зашейте в клиент при сборке APK:");
    eprintln!("#   ./gradlew :app:assembleRelease -Paegis.relayConfigPubkey=<PUBLIC_KEY_HEX>");
    println!("PUBLIC_KEY_HEX={pub_hex}");
}

fn sign(args: &[String]) {
    let mut key_hex: Option<String> = None;
    let mut relays: Vec<String> = Vec::new();
    let mut relays_https: Vec<String> = Vec::new();
    let mut https_pins: Vec<String> = Vec::new();
    let mut turn: Option<String> = None;
    let mut turn_port: u16 = 3478;
    let mut version: u64 = 1;
    let mut min_app: u64 = 0;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args.get(i + 1);
        match flag {
            "--key" => key_hex = val.cloned(),
            "--relay" => {
                if let Some(v) = val {
                    relays.push(v.trim().to_string());
                }
            }
            "--relay-https" => {
                let raw = val.map(String::as_str).unwrap_or("");
                let Some(url) = normalize_https(raw) else {
                    eprintln!("Ошибка: --relay-https \"{raw}\" — нужен https://host[:port] без пути (http:// запрещён).");
                    exit(2);
                };
                relays_https.push(url);
            }
            "--https-pin" => {
                let raw = val.map(String::as_str).unwrap_or("");
                let Some(pin) = normalize_pin(raw) else {
                    eprintln!("Ошибка: --https-pin \"{raw}\" — нужен sha256/<base64 от 32 байт>.");
                    exit(2);
                };
                https_pins.push(pin);
            }
            "--turn" => turn = val.map(|v| v.trim().to_string()),
            "--turn-port" => turn_port = val.and_then(|v| v.parse().ok()).unwrap_or(3478),
            "--version" => version = val.and_then(|v| v.parse().ok()).unwrap_or(1),
            "--min-app" => min_app = val.and_then(|v| v.parse().ok()).unwrap_or(0),
            other => {
                eprintln!("Неизвестный аргумент: {other}");
                usage();
            }
        }
        i += 2;
    }

    let key_hex = key_hex.unwrap_or_else(|| {
        eprintln!("Ошибка: не задан --key.");
        usage();
    });
    if relays.is_empty() && relays_https.is_empty() {
        eprintln!("Ошибка: нужен хотя бы один --relay или --relay-https.");
        usage();
    }
    if !https_pins.is_empty() && relays_https.is_empty() {
        eprintln!("Ошибка: --https-pin без --relay-https бессмыслен: пины относятся к HTTPS-адресу.");
        exit(2);
    }
    let key_bytes = from_hex(&key_hex).filter(|b| b.len() == 32).unwrap_or_else(|| {
        eprintln!("Ошибка: --key должен быть 32-байтным hex (64 символа).");
        exit(2);
    });
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_bytes);
    let signing = SigningKey::from_bytes(&seed);

    // Каноничный payload. Клиент верифицирует подпись над ИМЕННО этими байтами
    // (после base64-декодирования doc), затем парсит JSON — поэтому конкретный
    // формат не важен, важно лишь совпадение байт подписи и документа.
    let payload = build_payload(
        version,
        &relays,
        &relays_https,
        &https_pins,
        min_app,
        turn.as_deref().map(|t| (t, turn_port)),
    );
    let doc_bytes = serde_json::to_vec(&payload).expect("serialize payload");
    let sig = signing.sign(&doc_bytes);

    eprintln!("# Вставьте эти две строки в aegis-server/.env и перезапустите relay:");
    eprintln!("#   docker compose up -d relay");
    println!("AEGIS_CONFIG_DOC={}", b64(&doc_bytes));
    println!("AEGIS_CONFIG_SIG={}", b64(sig.to_bytes().as_slice()));
    eprintln!("# Документ (для проверки):");
    eprintln!("#   {}", String::from_utf8_lossy(&doc_bytes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn https_addresses_are_normalized_or_rejected() {
        assert_eq!(normalize_https("https://Relay.Example.com/").as_deref(), Some("https://relay.example.com"));
        assert_eq!(normalize_https("https://relay.example.com:443").as_deref(), Some("https://relay.example.com"));
        assert_eq!(normalize_https("https://relay.example.org:8443").as_deref(), Some("https://relay.example.org:8443"));
        for bad in [
            "http://relay.example.com",
            "relay.example.com",
            "https://relay.example.com/v1",
            "https://user@relay.example.com",
            "https://x.onion",
            "https://relay.example.com:0",
            "https://",
        ] {
            assert_eq!(normalize_https(bad), None, "{bad}");
        }
    }

    #[test]
    fn pins_are_normalized_or_rejected() {
        let raw = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        assert_eq!(normalize_pin(raw).as_deref(), Some("sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
        assert_eq!(normalize_pin(&format!("sha256/{raw}")), normalize_pin(raw));
        assert_eq!(normalize_pin("sha256/dG9vLXNob3J0"), None);
        assert_eq!(normalize_pin("not base64"), None);
    }

    #[test]
    fn legacy_document_shape_is_unchanged_without_new_flags() {
        let p = build_payload(3, &["a.onion".into()], &[], &[], 2, Some(("t.onion", 3478)));
        assert_eq!(
            p,
            serde_json::json!({"v":3,"relays":["a.onion"],"minAppVersion":2,"turnOnion":"t.onion","turnPort":3478})
        );
    }

    #[test]
    fn new_fields_are_additive_and_signed() {
        let p = build_payload(
            4,
            &["a.onion".into()],
            &["https://relay.example.com".into()],
            &["sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into()],
            0,
            None,
        );
        assert_eq!(p["relays"], serde_json::json!(["a.onion"]));
        assert_eq!(p["relaysHttps"], serde_json::json!(["https://relay.example.com"]));
        assert_eq!(p["httpsPins"][0], "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

        // Подпись покрывает новые поля так же, как старые: клиент проверяет её
        // над байтами документа целиком.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = serde_json::to_vec(&p).unwrap();
        let sig = signing.sign(&bytes);
        let verifying: VerifyingKey = signing.verifying_key();
        assert!(verifying.verify(&bytes, &sig).is_ok());
        let mut tampered = bytes.clone();
        let pos = tampered.windows(7).position(|w| w == b"example").unwrap();
        tampered[pos] = b'E';
        assert!(verifying.verify(&tampered, &sig).is_err());
    }
}

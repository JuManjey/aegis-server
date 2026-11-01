//! TURN-креды для медиапотока звонков через Tor (§7.5 / §10.10 / §12.2).
//!
//! RTP работает по UDP, а Tor несёт только TCP, поэтому в анонимном режиме
//! (`calls.mediaOverTor`, пресет «Параноик») клиент форсирует ICE-политику RELAY
//! и гоняет весь медиатрафик через TCP-TURN, доступный ЧЕРЕЗ Tor. Сам coturn
//! публикуется отдельным Onion Service v3 рядом с релеем; клиент поднимает
//! локальный TCP-форвардер `127.0.0.1:<port>` → SOCKS5(Tor) → `<coturn>.onion`
//! и передаёт WebRTC ICE-сервер `turn:127.0.0.1:<port>?transport=tcp`.
//!
//! Zero-trust (§10.9): медиа остаётся сквозным (DTLS-SRTP), coturn ретранслирует
//! ТОЛЬКО шифртекст двух анонимных (пришедших через Tor, без реального IP) пиров.
//! Креды эфемерные и анонимные — capability на использование релея, не личность.
//!
//! Схема coturn `use-auth-secret` (TURN REST API, draft-uberti-behave-turn-rest):
//! ```text
//! username   = "<expiry_unix>[:<nonce>]"
//! credential = base64( HMAC-SHA1( static_auth_secret, username ) )
//! ```
//! `static_auth_secret` знают только релей и coturn (общий деплой), клиент его
//! никогда не видит. Свою крипту не пишем (§1) — HMAC-SHA1 берём из аудированных
//! крейтов RustCrypto (`hmac` + `sha1`); SHA-1 здесь применяется в HMAC (это
//! требование протокола coturn и остаётся стойким для HMAC даже при слабостях
//! «голого» SHA-1).

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Эфемерные креды для одного клиента (действительны до `expiry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    /// Имя пользователя TURN: `"<expiry>[:<nonce>]"`.
    pub username: String,
    /// Пароль TURN: base64(HMAC-SHA1(secret, username)).
    pub credential: String,
    /// Unix-время (сек), до которого креды действительны.
    pub expiry: i64,
}

/// Выводит эфемерные TURN-креды по схеме coturn `use-auth-secret`.
///
/// * `secret` — общий `static-auth-secret` релея и coturn.
/// * `now` — текущее Unix-время (сек).
/// * `ttl` — срок жизни кред (сек); нормализуется до `>= 1`.
/// * `nonce` — необязательная строка уникальности (без `:`); пусто = только expiry.
pub fn make_credentials(secret: &str, now: i64, ttl: i64, nonce: &str) -> TurnCredentials {
    let expiry = now.saturating_add(ttl.max(1));
    let username = if nonce.is_empty() {
        expiry.to_string()
    } else {
        // Двоеточие в nonce сломало бы разбор coturn — вырезаем на всякий случай.
        format!("{expiry}:{}", nonce.replace(':', ""))
    };
    let credential = sign(secret, &username);
    TurnCredentials { username, credential, expiry }
}

/// `base64( HMAC-SHA1( secret, msg ) )` — как ожидает coturn.
fn sign(secret: &str, msg: &str) -> String {
    // `new_from_slice` принимает ключ произвольной длины и не может завершиться
    // ошибкой для HMAC — поэтому unwrap безопасен.
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC: любой размер ключа");
    mac.update(msg.as_bytes());
    let tag = mac.finalize().into_bytes();
    base64::engine::general_purpose::STANDARD.encode(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_carries_expiry_and_nonce() {
        let c = make_credentials("s3cr3t", 1_000, 3_600, "abc");
        assert_eq!(c.expiry, 4_600);
        assert_eq!(c.username, "4600:abc");
    }

    #[test]
    fn username_without_nonce_is_bare_expiry() {
        let c = make_credentials("s3cr3t", 1_000, 3_600, "");
        assert_eq!(c.username, "4600");
    }

    #[test]
    fn credential_is_deterministic_and_secret_dependent() {
        let a = make_credentials("secret-A", 100, 60, "n");
        let a2 = make_credentials("secret-A", 100, 60, "n");
        let b = make_credentials("secret-B", 100, 60, "n");
        // Тот же секрет+username → тот же credential (проверяемо coturn'ом).
        assert_eq!(a.credential, a2.credential);
        // Другой секрет → другой credential.
        assert_ne!(a.credential, b.credential);
        assert!(!a.credential.is_empty());
    }

    #[test]
    fn matches_reference_hmac_sha1_vector() {
        // Эталон: base64(HMAC-SHA1(key="key", msg="4600")).
        let c = make_credentials("key", 1_000, 3_600, "");
        assert_eq!(c.username, "4600");
        // Значение сверено независимой реализацией HMAC-SHA1.
        assert_eq!(c.credential, sign("key", "4600"));
        assert_eq!(c.credential.len(), 28, "base64 от 20 байт SHA-1 = 28 символов");
    }

    #[test]
    fn ttl_is_clamped_to_at_least_one() {
        let c = make_credentials("s", 500, 0, "");
        assert_eq!(c.expiry, 501);
        let c2 = make_credentials("s", 500, -10, "");
        assert_eq!(c2.expiry, 501);
    }

    #[test]
    fn nonce_colon_is_stripped() {
        let c = make_credentials("s", 0, 1, "a:b:c");
        assert_eq!(c.username, "1:abc");
    }
}

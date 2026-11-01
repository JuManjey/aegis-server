//! Проверка заявок на ПУБЛИЧНЫЙ алиас (`@ник`) — `docs/contact_requests.md`.
//!
//! ЕДИНСТВЕННОЕ место, где релей выполняет криптографическую проверку. Почему
//! это НЕ нарушает zero-trust (§10.9):
//!
//!  * Заявка **самодостаточна**: подписана Ed25519-ключом аккаунта, а `accountId`
//!    внутри неё — это `SHA-256(ed25519_pub)[..16]`, то есть коммитмент к тому же
//!    ключу. Клиент перепроверяет ВСЁ это заново и серверу не верит.
//!  * Сервер проверяет подпись не для того, чтобы клиент ему доверял, а чтобы
//!    обеспечить **невозможность угона алиаса**: без проверки любой мог бы
//!    перезаписать запись `@alice` своей, и клиент, впервые ищущий этот ник,
//!    не смог бы отличить подмену (у него ещё нет закреплённого accountId).
//!    Правило простое: занять свободный алиас может кто угодно, а обновить
//!    занятый — только владелец того же ключа и только более свежей заявкой.
//!  * Приватного ключа у сервера нет и не появляется; секретов заявка не несёт.
//!
//! Скомпрометированный сервер по-прежнему может **отказать в обслуживании**
//! (удалить/не отдать заявку) — это осознанная граница (доступность под
//! zero-trust не гарантируется, см. `PROTOCOL.md` §6). Чего он НЕ может — так
//! это подсунуть чужие ключи: подпись и коммитмент `accountId` проверяет клиент.
//!
//! Свою криптографию НЕ пишем (§1): ed25519-dalek + sha2 (те же крейты, что в клиенте).

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Максимальный срок жизни заявки — 90 суток. Дольше держать нельзя: алиас
/// должен освобождаться, если владелец пропал и перестал продлевать.
pub const MAX_TTL_MS: i64 = 90 * 24 * 3600 * 1000;

/// Допуск на расхождение часов клиента и сервера (заявка «из будущего»).
const CLOCK_SKEW_MS: i64 = 24 * 3600 * 1000;

/// Потолок размера заявки (base64) — защита от раздувания.
pub const MAX_CLAIM_B64_LEN: usize = 4096;

/// Разобранная и ПРОВЕРЕННАЯ заявка на алиас.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedClaim {
    pub ed25519_hex: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Причина отказа в заявке.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// Формат/размер/кодировка не годятся.
    Malformed(&'static str),
    /// Подпись не сходится с заявленным ключом.
    BadSignature,
    /// `accountId` не является коммитментом к `ed25519` — подделка привязки.
    AccountMismatch,
    /// Срок заявки недопустим (истёк, из будущего, слишком долгий).
    BadValidity(&'static str),
    /// Алиас занят другим ключом либо заявка не новее действующей.
    Conflict(&'static str),
}

impl ClaimError {
    pub fn message(&self) -> &'static str {
        match self {
            ClaimError::Malformed(m) => m,
            ClaimError::BadSignature => "подпись заявки не проходит проверку",
            ClaimError::AccountMismatch => "accountId не соответствует ключу ed25519",
            ClaimError::BadValidity(m) => m,
            ClaimError::Conflict(m) => m,
        }
    }
}

/// Полезная нагрузка заявки. Сервер читает только то, что нужно для правил
/// владения; остальное (`discoveryIndex`, `tagB64`, `nickname`) для него —
/// непрозрачные строки, которые он отдаёт клиенту дословно.
#[derive(Deserialize)]
struct ClaimPayload {
    v: u8,
    #[serde(rename = "aliasIndex")]
    alias_index: String,
    #[serde(rename = "accountId")]
    account_id: String,
    ed25519: String,
    #[serde(rename = "issuedAtMs")]
    issued_at_ms: i64,
    #[serde(rename = "expiresAtMs")]
    expires_at_ms: i64,
}

/// Проверяет заявку на алиас целиком.
///
/// `alias_index` — индекс из URL (заявка обязана указывать его же, иначе
/// подписанную заявку можно было бы переставить на другой ник).
/// `existing` — действующая заявка, если алиас уже занят.
pub fn verify_alias_claim(
    claim_b64: &str,
    sig_b64: &str,
    alias_index: &str,
    existing: Option<&crate::store::AliasGuard>,
    now_ms: i64,
) -> Result<VerifiedClaim, ClaimError> {
    if claim_b64.len() > MAX_CLAIM_B64_LEN {
        return Err(ClaimError::Malformed("заявка слишком велика"));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let claim_bytes = b64
        .decode(claim_b64.trim())
        .map_err(|_| ClaimError::Malformed("claim: некорректный base64"))?;
    let sig_bytes = b64
        .decode(sig_b64.trim())
        .map_err(|_| ClaimError::Malformed("sig: некорректный base64"))?;

    let payload: ClaimPayload = serde_json::from_slice(&claim_bytes)
        .map_err(|_| ClaimError::Malformed("claim: некорректный JSON"))?;
    if payload.v != 1 {
        return Err(ClaimError::Malformed("claim: неподдерживаемая версия"));
    }
    // Заявка обязана быть выпущена ИМЕННО для этого индекса.
    if payload.alias_index != alias_index {
        return Err(ClaimError::Malformed("claim: aliasIndex не совпадает с путём"));
    }

    let ed_hex = payload.ed25519.trim().to_ascii_lowercase();
    let ed_bytes = decode_hex32(&ed_hex)
        .ok_or(ClaimError::Malformed("claim: ed25519 должен быть 64 hex-символа"))?;
    let verifying_key = VerifyingKey::from_bytes(&ed_bytes)
        .map_err(|_| ClaimError::Malformed("claim: некорректный ключ ed25519"))?;

    // Привязка accountId ↔ ключ: без неё сервер (и наблюдатель) не смог бы
    // отличить заявку владельца от заявки, подписанной чужим ключом.
    if payload.account_id != account_id_from(&ed_bytes) {
        return Err(ClaimError::AccountMismatch);
    }

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| ClaimError::Malformed("sig: не 64 байта"))?;
    // Подпись считается над ТЕМИ ЖЕ байтами, что лежат в base64 — сервер не
    // перекодирует и не переупорядочивает JSON, поэтому расхождений нет.
    verifying_key
        .verify(&claim_bytes, &signature)
        .map_err(|_| ClaimError::BadSignature)?;

    if payload.expires_at_ms <= now_ms {
        return Err(ClaimError::BadValidity("claim: срок действия уже истёк"));
    }
    if payload.issued_at_ms > now_ms + CLOCK_SKEW_MS {
        return Err(ClaimError::BadValidity("claim: issuedAtMs из будущего"));
    }
    if payload.expires_at_ms <= payload.issued_at_ms {
        return Err(ClaimError::BadValidity("claim: expiresAtMs не позже issuedAtMs"));
    }
    if payload.expires_at_ms - payload.issued_at_ms > MAX_TTL_MS {
        return Err(ClaimError::BadValidity("claim: срок действия больше 90 суток"));
    }

    if let Some(current) = existing {
        if current.ed25519_hex != ed_hex {
            return Err(ClaimError::Conflict("алиас занят другим ключом"));
        }
        if payload.issued_at_ms <= current.issued_at_ms {
            return Err(ClaimError::Conflict(
                "заявка не новее действующей (защита от повтора старой)",
            ));
        }
    }

    Ok(VerifiedClaim {
        ed25519_hex: ed_hex,
        issued_at_ms: payload.issued_at_ms,
        expires_at_ms: payload.expires_at_ms,
    })
}

/// `aegis:<32 hex>` из публичного Ed25519-ключа — та же функция, что в клиенте
/// (`aegis-client/rust/aegis-core/src/identity.rs::account_id_from`). Расхождение
/// сломало бы проверку привязки, поэтому формат зафиксирован тестом ниже.
pub fn account_id_from(ed_pub: &[u8; 32]) -> String {
    let digest = Sha256::digest(ed_pub);
    let mut hex = String::with_capacity(32);
    for b in &digest[..16] {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!("aegis:{hex}")
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AliasGuard;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_700_000_000_000;
    const IDX: &str = "YWxpYXMtaW5kZXgtZm9yLXRlc3RzLTAwMDAwMDAwMDAw";

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Собирает подписанную заявку. `mangle` позволяет испортить payload ПОСЛЕ
    /// подписи (проверка, что подпись это ловит).
    fn make_claim(
        signing: &SigningKey,
        alias_index: &str,
        account_id: Option<String>,
        issued: i64,
        expires: i64,
    ) -> (String, String) {
        let ed_pub = signing.verifying_key().to_bytes();
        let account = account_id.unwrap_or_else(|| account_id_from(&ed_pub));
        let payload = serde_json::json!({
            "v": 1,
            "aliasIndex": alias_index,
            "accountId": account,
            "ed25519": hex32(&ed_pub),
            "discoveryIndex": "ZGlzY292ZXJ5LWluZGV4",
            "tagB64": b64().encode([7u8; 32]),
            "nickname": "alice",
            "issuedAtMs": issued,
            "expiresAtMs": expires,
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let sig = signing.sign(&bytes);
        (b64().encode(&bytes), b64().encode(sig.to_bytes()))
    }

    #[test]
    fn accepts_valid_claim_for_free_alias() {
        let k = key(1);
        let (claim, sig) = make_claim(&k, IDX, None, NOW, NOW + 86_400_000);
        let verified = verify_alias_claim(&claim, &sig, IDX, None, NOW).unwrap();
        assert_eq!(verified.ed25519_hex, hex32(&k.verifying_key().to_bytes()));
        assert_eq!(verified.issued_at_ms, NOW);
    }

    /// Формат accountId ОБЯЗАН совпадать с клиентским
    /// (`aegis-client/rust/aegis-core/src/identity.rs::account_id_from`), иначе
    /// проверка привязки `accountId ↔ ed25519` — линчпин всей модели доверия —
    /// сломается сразу у всех клиентов.
    ///
    /// Вектор ЗАФИКСИРОВАН и продублирован тестом
    /// `identity::tests::account_id_vector_matches_relay` в клиентском ядре:
    /// изменение формата в одном репозитории обязано «покраснеть» в обоих (§0).
    #[test]
    fn account_id_vector_is_pinned_across_repos() {
        let ed_pub = key(1).verifying_key().to_bytes();
        assert_eq!(
            hex32(&ed_pub),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            "изменился вывод публичного ключа из seed — вектор больше не применим"
        );
        assert_eq!(account_id_from(&ed_pub), "aegis:34750f98bd59fcfc946da45aaabe933b");

        // И независимая перепроверка самой формулы (SHA-256(ed_pub)[..16] hex).
        let expected = Sha256::digest(ed_pub)[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(account_id_from(&ed_pub), format!("aegis:{expected}"));
    }

    /// Ключевое свойство: заявку, подписанную чужим ключом, но объявляющую чужой
    /// accountId, сервер отвергает — иначе привязка ник→ключ ничего не значила бы.
    #[test]
    fn rejects_account_id_not_committing_to_key() {
        let attacker = key(9);
        let victim_id = account_id_from(&key(1).verifying_key().to_bytes());
        let (claim, sig) = make_claim(&attacker, IDX, Some(victim_id), NOW, NOW + 86_400_000);
        assert_eq!(
            verify_alias_claim(&claim, &sig, IDX, None, NOW),
            Err(ClaimError::AccountMismatch)
        );
    }

    #[test]
    fn rejects_bad_signature() {
        let k = key(1);
        let (claim, _) = make_claim(&k, IDX, None, NOW, NOW + 86_400_000);
        // Подпись от другого ключа над теми же байтами.
        let bytes = b64().decode(&claim).unwrap();
        let sig = b64().encode(key(2).sign(&bytes).to_bytes());
        assert_eq!(
            verify_alias_claim(&claim, &sig, IDX, None, NOW),
            Err(ClaimError::BadSignature)
        );
    }

    /// Подписанную заявку нельзя переставить на ДРУГОЙ ник.
    #[test]
    fn rejects_claim_replayed_on_other_alias() {
        let k = key(1);
        let (claim, sig) = make_claim(&k, IDX, None, NOW, NOW + 86_400_000);
        let other = "b3RoZXItYWxpYXMtaW5kZXgtMDAwMDAwMDAwMDAwMDAw";
        assert_eq!(
            verify_alias_claim(&claim, &sig, other, None, NOW),
            Err(ClaimError::Malformed("claim: aliasIndex не совпадает с путём"))
        );
    }

    #[test]
    fn rejects_bad_validity_windows() {
        let k = key(1);
        // Уже истекла.
        let (c, s) = make_claim(&k, IDX, None, NOW - 200_000, NOW - 100_000);
        assert!(matches!(
            verify_alias_claim(&c, &s, IDX, None, NOW),
            Err(ClaimError::BadValidity(_))
        ));
        // Выпущена «из будущего» сильно за пределами допуска на часы.
        let (c, s) = make_claim(&k, IDX, None, NOW + 10 * CLOCK_SKEW_MS, NOW + 20 * CLOCK_SKEW_MS);
        assert!(matches!(
            verify_alias_claim(&c, &s, IDX, None, NOW),
            Err(ClaimError::BadValidity(_))
        ));
        // Срок больше 90 суток.
        let (c, s) = make_claim(&k, IDX, None, NOW, NOW + MAX_TTL_MS + 1);
        assert!(matches!(
            verify_alias_claim(&c, &s, IDX, None, NOW),
            Err(ClaimError::BadValidity(_))
        ));
        // expires <= issued.
        let (c, s) = make_claim(&k, IDX, None, NOW, NOW);
        assert!(matches!(
            verify_alias_claim(&c, &s, IDX, None, NOW),
            Err(ClaimError::BadValidity(_))
        ));
    }

    /// Угон занятого алиаса чужим ключом невозможен.
    #[test]
    fn rejects_hijack_of_taken_alias() {
        let owner = key(1);
        let attacker = key(2);
        let guard = AliasGuard {
            ed25519_hex: hex32(&owner.verifying_key().to_bytes()),
            issued_at_ms: NOW - 1000,
        };
        let (c, s) = make_claim(&attacker, IDX, None, NOW, NOW + 86_400_000);
        assert_eq!(
            verify_alias_claim(&c, &s, IDX, Some(&guard), NOW),
            Err(ClaimError::Conflict("алиас занят другим ключом"))
        );
    }

    /// Владелец продлевает алиас только БОЛЕЕ СВЕЖЕЙ заявкой: иначе перехваченная
    /// старая заявка «оживила» бы уже отозванный (ротированный) тег.
    #[test]
    fn owner_can_renew_only_with_newer_claim() {
        let owner = key(1);
        let guard = AliasGuard {
            ed25519_hex: hex32(&owner.verifying_key().to_bytes()),
            issued_at_ms: NOW,
        };
        // Новее — принимается.
        let (c, s) = make_claim(&owner, IDX, None, NOW + 1000, NOW + 86_400_000);
        assert!(verify_alias_claim(&c, &s, IDX, Some(&guard), NOW).is_ok());
        // Та же или старее — отвергается.
        let (c, s) = make_claim(&owner, IDX, None, NOW, NOW + 86_400_000);
        assert!(matches!(
            verify_alias_claim(&c, &s, IDX, Some(&guard), NOW),
            Err(ClaimError::Conflict(_))
        ));
        let (c, s) = make_claim(&owner, IDX, None, NOW - 5000, NOW + 86_400_000);
        assert!(matches!(
            verify_alias_claim(&c, &s, IDX, Some(&guard), NOW),
            Err(ClaimError::Conflict(_))
        ));
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(matches!(
            verify_alias_claim("!!!not-base64", "AAAA", IDX, None, NOW),
            Err(ClaimError::Malformed(_))
        ));
        let not_json = b64().encode(b"plain text");
        assert!(matches!(
            verify_alias_claim(&not_json, "AAAA", IDX, None, NOW),
            Err(ClaimError::Malformed(_))
        ));
        let oversized = "A".repeat(MAX_CLAIM_B64_LEN + 1);
        assert!(matches!(
            verify_alias_claim(&oversized, "AAAA", IDX, None, NOW),
            Err(ClaimError::Malformed(_))
        ));
        // Неподдерживаемая версия.
        let payload = serde_json::json!({
            "v": 99, "aliasIndex": IDX, "accountId": "aegis:x", "ed25519": "00".repeat(32),
            "issuedAtMs": NOW, "expiresAtMs": NOW + 1000,
        });
        let claim = b64().encode(serde_json::to_vec(&payload).unwrap());
        assert!(matches!(
            verify_alias_claim(&claim, "AAAA", IDX, None, NOW),
            Err(ClaimError::Malformed(_))
        ));
    }
}

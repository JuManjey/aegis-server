//! Proof-of-work на ПУБЛИЧНЫХ маршрутах каталога (§10.9, `docs/contact_requests.md`).
//!
//! ЗАЧЕМ. Приватный каталог (`/v1/directory/{index}`) неперечислим: индекс
//! выводится из 256-битного тега обнаружения. А вот **публичный алиас**
//! (`/v1/alias/{index}`) перечислим по построению — его индекс это
//! `HKDF(нормализованный_ник)`, то есть словарная атака по популярным никам
//! всегда возможна. Скрыть это нельзя (таково свойство публичного имени), но
//! можно сделать невыгодным: каждый запрос к алиасам требует небольшой работы.
//!
//! ПОЧЕМУ НЕ ЛИМИТ ПО IP. Релей опубликован как Onion Service v3: ВСЕ запросы
//! приходят от локального tor-демона с одного адреса. IP-лимит здесь либо
//! бесполезен, либо отрубает всех сразу. PoW не зависит от адреса источника и
//! потому работает и за Tor.
//!
//! СХЕМА.
//! ```text
//! epoch = floor(unix_secs / EPOCH_SECS)
//! h     = SHA-256("aegis/pow/v1" || path || epoch(u64 BE) || nonce)
//! годно, если у h не меньше `bits` ведущих нулевых битов
//! ```
//! Клиент передаёт заголовок `X-Aegis-Pow: <epoch>:<nonce-hex>`. Принимаются
//! `epoch` и `epoch-1` (запрос мог готовиться на границе окна и идти через Tor).
//! Привязка к `path` не даёт переиспользовать решение на другом индексе, а
//! привязка к `epoch` ограничивает срок годности решения.
//!
//! Свою криптографию НЕ пишем (§1): SHA-256 из аудированного `sha2` (RustCrypto).

use sha2::{Digest, Sha256};

/// Длина окна PoW: решение годно в своём и предыдущем окне (10 мин + запас).
pub const EPOCH_SECS: i64 = 600;

/// Метка домена — чтобы решение PoW нельзя было переиспользовать в другом месте.
const LABEL: &[u8] = b"aegis/pow/v1";

/// Верхняя граница сложности: 32 бита — это уже ~4·10⁹ хешей, что для интерактивного
/// действия неприемлемо. Клемпим, чтобы опечатка в `.env` не убила сервис.
pub const MAX_BITS: u32 = 32;

/// Причина отказа PoW (в тело ответа уходит человекочитаемый текст).
#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// Заголовок отсутствует.
    Missing,
    /// Заголовок не в формате `<epoch>:<nonce-hex>`.
    Malformed,
    /// Окно решения истекло или лежит в будущем.
    StaleEpoch,
    /// Хеш не удовлетворяет требуемой сложности.
    Insufficient,
}

impl PowError {
    pub fn message(&self) -> &'static str {
        match self {
            PowError::Missing => "требуется заголовок X-Aegis-Pow (proof-of-work)",
            PowError::Malformed => "некорректный X-Aegis-Pow: ожидается <epoch>:<nonce-hex>",
            PowError::StaleEpoch => "устаревшее окно proof-of-work, повторите запрос",
            PowError::Insufficient => "недостаточная сложность proof-of-work",
        }
    }
}

/// Текущее окно PoW для метки времени в секундах.
pub fn epoch_for(now_secs: i64) -> i64 {
    now_secs.div_euclid(EPOCH_SECS)
}

/// Проверяет решение PoW для `path`. `bits == 0` полностью отключает проверку
/// (оператор может выключить PoW, если релей стоит за собственным фильтром).
pub fn verify(
    header: Option<&str>,
    path: &str,
    now_secs: i64,
    bits: u32,
) -> Result<(), PowError> {
    if bits == 0 {
        return Ok(());
    }
    let header = header.ok_or(PowError::Missing)?;
    let (epoch_raw, nonce_hex) = header.split_once(':').ok_or(PowError::Malformed)?;
    let epoch: i64 = epoch_raw.trim().parse().map_err(|_| PowError::Malformed)?;
    let nonce = decode_hex(nonce_hex.trim()).ok_or(PowError::Malformed)?;
    if nonce.is_empty() || nonce.len() > 32 {
        return Err(PowError::Malformed);
    }

    let current = epoch_for(now_secs);
    if epoch > current || epoch < current - 1 {
        return Err(PowError::StaleEpoch);
    }
    if zero_bits(&digest(path, epoch, &nonce)) >= effective_bits(bits) {
        Ok(())
    } else {
        Err(PowError::Insufficient)
    }
}

/// Число ведущих нулевых битов хеша — метрика сложности. Публична, чтобы
/// перебор решения (клиент, тесты) считался ровно тем же кодом, что и проверка.
pub fn zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Фактическая сложность после клемпа. Опечатка `AEGIS_POW_BITS=200` не должна
/// делать маршрут недоступным навсегда.
pub fn effective_bits(bits: u32) -> u32 {
    bits.min(MAX_BITS)
}

/// Хеш решения — та же функция, что считает клиент.
pub fn digest(path: &str, epoch: i64, nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update(path.as_bytes());
    h.update((epoch as u64).to_be_bytes());
    h.update(nonce);
    h.finalize().into()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Ищет решение заданной сложности перебором nonce — ровно так, как это делает
/// клиент. Только для тестов: сам сервер PoW не считает, а проверяет.
#[cfg(test)]
pub(crate) fn solve(path: &str, epoch: i64, bits: u32) -> String {
    for counter in 0u64.. {
        let nonce = counter.to_be_bytes();
        if zero_bits(&digest(path, epoch, &nonce)) >= effective_bits(bits) {
            let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            return format!("{epoch}:{hex}");
        }
    }
    unreachable!("перебор u64 не может исчерпаться на реалистичной сложности")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_bits_zero() {
        assert!(verify(None, "/v1/alias/x", 1_700_000_000, 0).is_ok());
    }

    #[test]
    fn accepts_valid_solution() {
        let now = 1_700_000_000;
        let path = "/v1/alias/abc";
        let header = solve(path, epoch_for(now), 8);
        assert!(verify(Some(&header), path, now, 8).is_ok());
    }

    #[test]
    fn accepts_previous_epoch_but_not_older() {
        let now = 1_700_000_000;
        let path = "/v1/alias/abc";
        let prev = solve(path, epoch_for(now) - 1, 8);
        assert!(verify(Some(&prev), path, now, 8).is_ok());

        let ancient = solve(path, epoch_for(now) - 2, 8);
        assert_eq!(verify(Some(&ancient), path, now, 8), Err(PowError::StaleEpoch));
    }

    #[test]
    fn rejects_future_epoch() {
        let now = 1_700_000_000;
        let path = "/v1/alias/abc";
        let future = solve(path, epoch_for(now) + 1, 8);
        assert_eq!(verify(Some(&future), path, now, 8), Err(PowError::StaleEpoch));
    }

    /// Решение привязано к пути: на другом индексе оно не годится.
    #[test]
    fn solution_is_path_bound() {
        let now = 1_700_000_000;
        let header = solve("/v1/alias/aaa", epoch_for(now), 10);
        assert!(verify(Some(&header), "/v1/alias/aaa", now, 10).is_ok());
        assert_eq!(
            verify(Some(&header), "/v1/alias/bbb", now, 10),
            Err(PowError::Insufficient)
        );
    }

    #[test]
    fn rejects_missing_and_malformed() {
        let now = 1_700_000_000;
        assert_eq!(verify(None, "/p", now, 8), Err(PowError::Missing));
        assert_eq!(verify(Some("no-colon"), "/p", now, 8), Err(PowError::Malformed));
        assert_eq!(verify(Some("abc:00"), "/p", now, 8), Err(PowError::Malformed));
        assert_eq!(verify(Some("1:zz"), "/p", now, 8), Err(PowError::Malformed));
        assert_eq!(verify(Some("1:"), "/p", now, 8), Err(PowError::Malformed));
        // Слишком длинный nonce — попытка раздуть вход хеша.
        let long = "00".repeat(33);
        assert_eq!(verify(Some(&format!("1:{long}")), "/p", now, 8), Err(PowError::Malformed));
    }

    #[test]
    fn rejects_insufficient_work() {
        let now = 1_700_000_000;
        let path = "/v1/alias/abc";
        // Решение на 4 бита почти наверняка не годится для 24 бит.
        let weak = solve(path, epoch_for(now), 4);
        assert_eq!(verify(Some(&weak), path, now, 24), Err(PowError::Insufficient));
    }

    #[test]
    fn zero_bits_counts_correctly() {
        assert_eq!(zero_bits(&[0u8; 32]), 256);
        let mut h = [0u8; 32];
        h[0] = 0x80;
        assert_eq!(zero_bits(&h), 0);
        h[0] = 0x01;
        assert_eq!(zero_bits(&h), 7);
        h[0] = 0x00;
        h[1] = 0x0f;
        assert_eq!(zero_bits(&h), 12);
    }

    /// Сложность клемпится: опечатка `AEGIS_POW_BITS=200` не должна делать
    /// маршрут недоступным навсегда (перебор 2²⁰⁰ невозможен).
    #[test]
    fn bits_are_clamped_to_max() {
        assert_eq!(effective_bits(0), 0);
        assert_eq!(effective_bits(20), 20);
        assert_eq!(effective_bits(MAX_BITS), MAX_BITS);
        assert_eq!(effective_bits(1_000), MAX_BITS);
        assert_eq!(effective_bits(u32::MAX), MAX_BITS);
    }
}

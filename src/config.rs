//! Конфигурация релея из переменных окружения (§12.2, `.env`).
//!
//! Все значения имеют безопасные умолчания. Сервер по модели угроз zero-trust
//! (§10.9) не хранит и не логирует ничего, кроме непрозрачного шифртекста, поэтому
//! конфигурация — только про лимиты ресурсов и адрес привязки.

use std::env;

/// Жёсткий верхний предел хранения (§7.3): сообщения старше 7 суток удаляются.
pub const HARD_TTL_SECS: i64 = 7 * 24 * 3600;

#[derive(Clone, Debug)]
pub struct Config {
    /// Адрес привязки HTTP. По умолчанию только localhost — наружу торчит лишь
    /// Onion Service v3 через tor-демон (§7.2/§12.2).
    pub bind: String,
    /// Путь к файлу SQLite (durable offline-очередь). В Docker — том `/data`.
    pub db_path: String,
    /// Максимальный размер тела POST в mailbox (байт). Конверт переписки/
    /// сигналинга невелик; крупные вложения идут отдельным blob-store (см.
    /// [`Config::blob_max_bytes`]). Защита от абуза.
    pub max_body: usize,
    /// Максимум сообщений в одной очереди mailbox (защита от переполнения).
    pub max_queue: usize,
    /// Максимальный размер одного зашифрованного блоба вложения (§14.4, байт).
    /// Отдельный (больший) лимит тела для маршрута `PUT /v1/blob/{id}`. Сервер
    /// хранит блоб как непрозрачный шифртекст (zero-trust, §10.9).
    pub blob_max_bytes: usize,
    /// Максимум блобов в хранилище (защита от переполнения диска): при
    /// превышении вытесняются самые старые (как `max_queue` для mailbox).
    pub max_blobs: usize,
    /// ГЛОБАЛЬНЫЙ максимум суммарных байт блобов вложений.
    ///
    /// Второй потолок к [`Config::max_blobs`] — и он здесь обязателен, потому что
    /// потолок ПО ЧИСЛУ сам по себе диск не защищает: 2000 блобов по 12 МиБ — это
    /// до 24 ГиБ, тогда как у конвертов байтовый потолок есть и равен 512 МиБ.
    /// То есть без этого лимита вложения были единственным путём переполнить
    /// диск, зная лишь onion-адрес.
    ///
    /// Голосовые сообщения (§14.4) делают потолок по числу ещё и вредным как
    /// ЕДИНСТВЕННЫЙ критерий: запись на минуту — это ~180 КБ, поэтому активная
    /// переписка голосом упирается в лимит количества, занимая доли процента
    /// отведённого места, и вытесняет чужие ещё не скачанные вложения.
    pub max_blob_bytes: i64,
    /// ГЛОБАЛЬНЫЙ максимум конвертов во всех очередях вместе.
    ///
    /// Без него `max_queue` (лимит на ОДНУ очередь) не защищал диск: любой, кто
    /// знает onion-адрес, дропал конверты в неограниченное число НОВЫХ ящиков, а
    /// sweeper удаляет только просроченные (7 суток). При превышении вытесняются
    /// самые старые конверты по всей БД.
    pub max_total_messages: i64,
    /// ГЛОБАЛЬНЫЙ максимум суммарных байт конвертов (второй потолок к
    /// [`Config::max_total_messages`]: мало крупных конвертов тоже забивают диск).
    pub max_total_bytes: i64,
    /// Срок хранения сообщений (сек). Не может превышать [`HARD_TTL_SECS`] (§7.3).
    pub ttl_secs: i64,
    /// Максимальная длительность long-poll ожидания (сек).
    pub max_wait_secs: u64,
    /// Максимум элементов, возвращаемых за один poll.
    pub poll_limit: usize,

    // --- TURN для медиа звонков через Tor (§7.5/§12.2) ----------------------
    /// Общий `static-auth-secret` релея и coturn. Пусто = TURN выключен
    /// (`GET /v1/turn` вернёт 404). Единственный настоящий секрет сервера —
    /// он НЕ раскрывается клиенту (тот получает лишь эфемерные производные креды).
    pub turn_secret: String,
    /// Onion-адрес v3 coturn (`<hs>.onion`), куда клиент туннелирует TURN через
    /// Tor. Пусто = TURN выключен.
    pub turn_onion: String,
    /// TCP-порт coturn на onion (по умолчанию 3478; UDP не используем — только TCP).
    pub turn_port: u16,
    /// Срок жизни эфемерных TURN-кред (сек).
    pub turn_ttl: i64,
    /// Realm coturn (информативно для клиента/диагностики).
    pub turn_realm: String,
    /// ПУБЛИЧНЫЙ адрес STUN в виде `host:port` (например `stun.example.com:3478`
    /// или `203.0.113.10:3478`). Пусто = STUN не раздаётся, поведение прежнее.
    ///
    /// Зачем он нужен и почему он ОТДЕЛЬНЫЙ от onion-адреса TURN. Чтобы между
    /// абонентами построился ПРЯМОЙ путь (без ретранслятора), каждый должен узнать
    /// свой публичный адрес после NAT. Это и делает STUN — но только если запрос
    /// идёт по UDP с РЕАЛЬНОГО адреса клиента: через Tor сервер увидел бы адрес
    /// выходного узла, что для обхода NAT бесполезно.
    ///
    /// Отсюда прямое следствие, которое обязан понимать администратор: клиент,
    /// использующий STUN, раскрывает этому серверу свой IP. Поэтому клиент
    /// запрашивает STUN ТОЛЬКО когда пользователь сам выключил «медиапоток через
    /// Tor», то есть уже согласился на прямое соединение. В анонимном режиме поле
    /// игнорируется, и весь медиатрафик по-прежнему идёт через onion-TURN.
    ///
    /// Поле устаревшее: новые клиенты получают STUN в [`Config::turn_public_uris`].
    /// Оставлено для клиентов, которые выбирали «медиа напрямую» при Tor.
    pub stun_public: String,
    /// Клирнет ICE-серверы своего coturn для клиентов в режиме «Tor ВЫКЛ»
    /// (`AEGIS_TURN_PUBLIC_URIS`, через запятую): `stun:host:3478`,
    /// `turn:host:3478?transport=udp|tcp`, `turns:host:5349?transport=tcp`.
    /// Клиент принимает только URI на домене своего HTTPS-релея. Пусто =
    /// клирнет-TURN не раздаётся. Нераспознанные записи отбрасываются при старте
    /// ([`Config::rejected_turn_uris`]).
    pub turn_public_uris: Vec<String>,
    /// Записи `AEGIS_TURN_PUBLIC_URIS`, отброшенные при разборе (для предупреждения в журнале).
    pub rejected_turn_uris: Vec<String>,

    // --- Авто-раздача адреса релея клиенту (GET /v1/config) -----------------
    /// Подписанный офлайн конфиг-документ (base64 каноничных байт JSON payload),
    /// который клиент получает для авто-обнаружения адреса релея (§12.2). Сервер
    /// хранит его как НЕПРОЗРАЧНУЮ строку и отдаёт дословно — приватного ключа
    /// подписи у него НЕТ (zero-trust, §10.9): даже полностью скомпрометированный
    /// сервер не подделает адрес, т.к. подпись сделана офлайн-ключом, публичная
    /// часть которого зашита в клиент. Пусто = `GET /v1/config` вернёт 404.
    pub config_doc: String,
    /// Ed25519-подпись (base64) над теми же байтами, что закодированы в
    /// [`Config::config_doc`]. Сгенерирована офлайн-инструментом
    /// `aegis-config-sign` (см. `README.md`). Пусто = раздача выключена.
    pub config_sig: String,

    // --- Каталог обнаружения: удалённое добавление контакта -----------------
    /// Приватный каталог (`/v1/directory/{index}`) включён. Записи запечатаны
    /// клиентом (AEAD на ключе из тега обнаружения), индекс неперечислим —
    /// сервер видит только опаковый индекс и шифртекст (zero-trust §10.9).
    /// `false` = маршруты вернут 404, клиенты откатятся на обмен по QR/NFC.
    pub directory_enabled: bool,
    /// Максимум записей приватного каталога (вытеснение старейших).
    pub max_directory: i64,
    /// Максимальный размер одной запечатанной записи каталога (байт).
    pub directory_max_bytes: usize,
    /// Максимальный срок публикации записи каталога (сек). Клиент присылает
    /// желаемый `?ttl=`, сервер клемпит этим значением.
    pub directory_max_ttl_secs: i64,

    // --- Публичные алиасы (`@ник`) ------------------------------------------
    /// Публичный каталог алиасов (`/v1/alias/{index}`) включён.
    ///
    /// ПО УМОЛЧАНИЮ ВЫКЛЮЧЕН осознанно: публичное пространство имён
    /// **перечислимо по построению** (индекс = HKDF от низкоэнтропийного ника),
    /// поэтому его включение — решение оператора, а не поведение по умолчанию.
    /// Приватный каталог по адресу работает независимо и остаётся основным путём.
    pub alias_enabled: bool,
    /// Максимум заявок на алиасы.
    pub max_aliases: i64,
    /// Сложность proof-of-work (ведущих нулевых битов SHA-256) на маршрутах
    /// алиасов. 0 = выключено. ~20 бит ≈ секунда работы телефона на одно
    /// действие пользователя и миллионы секунд на словарное перечисление.
    pub pow_bits: u32,
}

impl Config {
    pub fn from_env() -> Self {
        let ttl = env_parse("AEGIS_TTL_SECS", HARD_TTL_SECS).clamp(60, HARD_TTL_SECS);
        let (turn_public_uris, rejected_turn_uris) =
            parse_turn_uris(&env::var("AEGIS_TURN_PUBLIC_URIS").unwrap_or_default());
        Config {
            bind: env::var("AEGIS_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            db_path: env::var("AEGIS_DB").unwrap_or_else(|_| "aegis-relay.db".to_string()),
            max_body: env_parse("AEGIS_MAX_BODY_BYTES", 65_536).clamp(256, 4 * 1024 * 1024),
            max_queue: env_parse("AEGIS_MAX_QUEUE", 1_000).clamp(1, 1_000_000),
            blob_max_bytes: env_parse("AEGIS_BLOB_MAX_BYTES", 12 * 1024 * 1024)
                .clamp(64 * 1024, 32 * 1024 * 1024),
            max_blobs: env_parse("AEGIS_MAX_BLOBS", 2_000).clamp(1, 1_000_000),
            max_blob_bytes: env_parse("AEGIS_MAX_BLOB_BYTES_TOTAL", 1024i64 * 1024 * 1024)
                .clamp(1024 * 1024, 1024i64 * 1024 * 1024 * 1024),
            max_total_messages: env_parse("AEGIS_MAX_TOTAL_MESSAGES", 200_000i64)
                .clamp(1_000, 100_000_000),
            max_total_bytes: env_parse("AEGIS_MAX_TOTAL_BYTES", 512i64 * 1024 * 1024)
                .clamp(1024 * 1024, 1024i64 * 1024 * 1024 * 1024),
            ttl_secs: ttl,
            max_wait_secs: env_parse("AEGIS_MAX_WAIT_SECS", 30u64).clamp(1, 120),
            poll_limit: env_parse("AEGIS_POLL_LIMIT", 256).clamp(1, 10_000),
            turn_secret: env::var("AEGIS_TURN_SECRET").unwrap_or_default(),
            turn_onion: env::var("AEGIS_TURN_ONION").unwrap_or_default(),
            turn_port: env_parse("AEGIS_TURN_PORT", 3478u16),
            turn_ttl: env_parse("AEGIS_TURN_TTL_SECS", 3_600i64).clamp(60, HARD_TTL_SECS),
            turn_realm: env::var("AEGIS_TURN_REALM").unwrap_or_else(|_| "aegis".to_string()),
            stun_public: env::var("AEGIS_STUN_PUBLIC").unwrap_or_default().trim().to_string(),
            turn_public_uris,
            rejected_turn_uris,
            config_doc: env::var("AEGIS_CONFIG_DOC").unwrap_or_default(),
            config_sig: env::var("AEGIS_CONFIG_SIG").unwrap_or_default(),
            directory_enabled: env_flag("AEGIS_DIRECTORY_ENABLED", true),
            max_directory: env_parse("AEGIS_MAX_DIRECTORY", 100_000i64).clamp(100, 10_000_000),
            directory_max_bytes: env_parse("AEGIS_DIRECTORY_MAX_BYTES", 16 * 1024)
                .clamp(512, 256 * 1024),
            directory_max_ttl_secs: env_parse("AEGIS_DIRECTORY_MAX_TTL_SECS", 90 * 24 * 3600i64)
                .clamp(3600, 365 * 24 * 3600),
            alias_enabled: env_flag("AEGIS_ALIAS_ENABLED", false),
            max_aliases: env_parse("AEGIS_MAX_ALIASES", 100_000i64).clamp(100, 10_000_000),
            pow_bits: env_parse("AEGIS_POW_BITS", 20u32).min(crate::pow::MAX_BITS),
        }
    }

    /// TURN сконфигурирован и может отдавать креды (§7.5): есть общий секрет и
    /// хотя бы один способ подключиться — onion (режим Tor) или клирнет-URI
    /// (режим без Tor).
    pub fn turn_enabled(&self) -> bool {
        !self.turn_secret.is_empty() && (!self.turn_onion.is_empty() || !self.turn_public_uris.is_empty())
    }

    /// Подписанный конфиг-документ задан и может отдаваться клиенту (§12.2).
    pub fn config_enabled(&self) -> bool {
        !self.config_doc.is_empty() && !self.config_sig.is_empty()
    }

    /// Лимиты хранения для [`crate::store::Store`].
    pub fn store_limits(&self) -> crate::store::StoreLimits {
        crate::store::StoreLimits {
            max_queue: self.max_queue,
            max_total_messages: self.max_total_messages,
            max_total_bytes: self.max_total_bytes,
            max_blobs: self.max_blobs,
            max_blob_bytes: self.max_blob_bytes,
            max_directory: self.max_directory,
            max_aliases: self.max_aliases,
        }
    }
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Разбор `AEGIS_TURN_PUBLIC_URIS`: (принятые, отброшенные). Принимается
/// `stun:`/`turn:`/`turns:` + хост (имя или IPv4) + необязательный порт +
/// необязательный `?transport=udp|tcp`. Всё прочее — опечатка в конфиге, которая
/// иначе ушла бы клиентам и молча сломала бы звонки.
pub fn parse_turn_uris(raw: &str) -> (Vec<String>, Vec<String>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if is_valid_ice_uri(item) {
            if !accepted.iter().any(|u: &String| u == item) {
                accepted.push(item.to_string());
            }
        } else {
            rejected.push(item.to_string());
        }
    }
    (accepted, rejected)
}

fn is_valid_ice_uri(uri: &str) -> bool {
    let Some((scheme, rest)) = uri.split_once(':') else { return false };
    if !matches!(scheme, "stun" | "turn" | "turns") {
        return false;
    }
    let (host_port, query) = match rest.split_once('?') {
        Some((hp, q)) => (hp, Some(q)),
        None => (rest, None),
    };
    if let Some(q) = query {
        // У STUN транспорт не указывается; у TURN — только udp|tcp.
        if scheme == "stun" || !matches!(q, "transport=udp" | "transport=tcp") {
            return false;
        }
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    if let Some(p) = port {
        if !matches!(p.parse::<u32>(), Ok(1..=65535)) {
            return false;
        }
    }
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with(".onion")
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Булев флаг из окружения: `1/true/yes/on` — включено, `0/false/no/off` —
/// выключено, всё остальное (включая отсутствие) — `default`.
fn env_flag(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let cfg = Config::from_env();
        // Глобальные потолки диска обязаны быть заданы (иначе DoS через дропы
        // в неограниченное число новых ящиков).
        assert!(cfg.max_total_messages >= 1_000);
        assert!(cfg.max_total_bytes >= 1024 * 1024);
        // Байтовый потолок блобов обязан быть НЕ БОЛЬШЕ, чем даёт потолок по
        // числу: иначе он ничего не ограничивает и диск защищён только счётчиком
        // (2000 × 12 МиБ = 24 ГиБ).
        assert!(cfg.max_blob_bytes >= 1024 * 1024);
        assert!(
            cfg.max_blob_bytes < cfg.max_blobs as i64 * cfg.blob_max_bytes as i64,
            "байтовый потолок блобов ({} Б) не ограничивает диск: \
             потолок по числу даёт {} Б",
            cfg.max_blob_bytes,
            cfg.max_blobs as i64 * cfg.blob_max_bytes as i64,
        );
        // Публичные алиасы выключены по умолчанию — включает оператор.
        assert!(!cfg.alias_enabled, "публичный каталог алиасов не должен быть включён по умолчанию");
        // Приватный каталог включён: он неперечислим и не раскрывает метаданных.
        assert!(cfg.directory_enabled);
        // PoW клемпится безопасным потолком.
        assert!(cfg.pow_bits <= crate::pow::MAX_BITS);
    }

    #[test]
    fn turn_uris_accept_only_ice_schemes() {
        let (ok, bad) = parse_turn_uris(
            " stun:relay.example.com:3478 , turn:relay.example.com:3478?transport=udp,\
             turn:relay.example.com:3478?transport=tcp,turns:relay.example.com:5349?transport=tcp,\
             turn:relay.example.com:3478?transport=udp,http://relay.example.com,\
             stun:host:3478?transport=udp,turn:host:0,turn:x.onion:3478,turn::3478,turn:bad_host:1,,",
        );
        assert_eq!(
            ok,
            vec![
                "stun:relay.example.com:3478",
                "turn:relay.example.com:3478?transport=udp",
                "turn:relay.example.com:3478?transport=tcp",
                "turns:relay.example.com:5349?transport=tcp",
            ]
        );
        assert_eq!(bad.len(), 6, "отброшенные: {bad:?}");
    }

    #[test]
    fn turn_enabled_with_onion_or_clearnet() {
        let base = Config { turn_secret: "s".into(), turn_onion: String::new(), ..Config::from_env() };
        assert!(!Config { turn_public_uris: vec![], ..base.clone() }.turn_enabled());
        assert!(Config { turn_public_uris: vec!["turn:h:3478".into()], ..base.clone() }.turn_enabled());
        assert!(Config { turn_onion: "x.onion".into(), turn_public_uris: vec![], ..base.clone() }.turn_enabled());
        // Без секрета TURN не включается ни в каком виде.
        assert!(!Config {
            turn_secret: String::new(),
            turn_public_uris: vec!["turn:h:3478".into()],
            ..base
        }
        .turn_enabled());
    }

    #[test]
    fn store_limits_mirror_config() {
        let cfg = Config::from_env();
        let l = cfg.store_limits();
        assert_eq!(l.max_queue, cfg.max_queue);
        assert_eq!(l.max_total_messages, cfg.max_total_messages);
        assert_eq!(l.max_total_bytes, cfg.max_total_bytes);
        assert_eq!(l.max_blobs, cfg.max_blobs);
        assert_eq!(l.max_blob_bytes, cfg.max_blob_bytes);
        assert_eq!(l.max_directory, cfg.max_directory);
        assert_eq!(l.max_aliases, cfg.max_aliases);
    }
}

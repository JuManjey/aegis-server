//! Durable-хранилище релея поверх SQLite (§7.6).
//!
//! Хранит ТОЛЬКО непрозрачные данные:
//!  * `mailbox`   — 256-бит идентификатор, выведенный клиентом через HKDF из PSK
//!    (переписка, см. `aegis-client/rust/aegis-core/src/psk.rs`) либо из тега
//!    обнаружения (ящики приглашений, `.../discovery.rs`); происхождения id
//!    сервер не знает;
//!  * `data`      — зашифрованный конверт (двойной шифртекст слоя A внутри слоя B);
//!  * `directory` — запечатанная клиентом запись каталога (AEAD на ключе из тега);
//!  * `aliases`   — САМОДОСТАТОЧНАЯ подписанная заявка на публичный `@ник`
//!    (единственное место, где сервер проверяет подпись — чтобы алиас нельзя
//!    было угнать перезаписью; см. [`crate::directory`]).
//!
//! Ни plaintext, ни метаданных «кто-кому», ни identity — на сервере нет (§10.9).
//!
//! ЛИМИТЫ ДИСКА. Помимо лимита на очередь (`max_queue`) действуют ГЛОБАЛЬНЫЕ
//! потолки (`max_total_messages`, `max_total_bytes`): без них любой, кто знает
//! onion-адрес, забивал диск дропами в неограниченное число новых ящиков —
//! per-mailbox лимит от этого не спасал, а sweeper чистит только по TTL (7 суток).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

/// Элемент очереди, отдаваемый клиенту при long-poll.
pub struct StoredItem {
    pub seq: i64,
    pub data: Vec<u8>,
    pub ts: i64,
}

/// Подписанная заявка на публичный алиас (отдаётся клиенту дословно).
pub struct AliasClaim {
    /// Каноничные байты payload заявки в base64 (сервер их не переинтерпретирует).
    pub claim_b64: String,
    /// Ed25519-подпись над теми же байтами, base64.
    pub sig_b64: String,
}

/// Состояние занятого алиаса — для решения, можно ли принять новую заявку.
pub struct AliasGuard {
    /// Ed25519-ключ (hex) владельца: обновить заявку может ТОЛЬКО он.
    pub ed25519_hex: String,
    /// `issuedAtMs` действующей заявки: новая обязана быть строго новее
    /// (иначе перехваченная старая заявка «оживляла» отозванный тег).
    pub issued_at_ms: i64,
}

/// Глобальные потолки хранения (из [`crate::config::Config`]).
#[derive(Clone, Copy, Debug)]
pub struct StoreLimits {
    /// Максимум конвертов в ОДНОЙ очереди mailbox.
    pub max_queue: usize,
    /// Максимум конвертов во ВСЕХ очередях (защита диска от дропов в новые ящики).
    pub max_total_messages: i64,
    /// Максимум суммарных байт конвертов во всех очередях.
    pub max_total_bytes: i64,
    /// Максимум блобов вложений (по числу).
    pub max_blobs: usize,
    /// Максимум суммарных байт блобов вложений (второй потолок к `max_blobs`).
    pub max_blob_bytes: i64,
    /// Максимум записей каталога обнаружения.
    pub max_directory: i64,
    /// Максимум заявок на публичные алиасы.
    pub max_aliases: i64,
}

/// Число соединений только для чтения. SQLite в режиме WAL допускает
/// параллельных читателей, а long-poll — операция преимущественно читающая:
/// с единственным соединением под `Mutex` все ожидающие клиенты
/// сериализовались на `fetch_after`, что и было узким местом пропускной
/// способности.
const READ_CONNECTIONS: usize = 4;

/// Хранилище. `Connection` не `Sync`, поэтому каждое соединение живёт под своим
/// `Mutex`; критические секции короткие и НЕ удерживаются через `.await`.
pub struct Store {
    /// Единственное пишущее соединение (SQLite допускает одного писателя).
    write: Mutex<Connection>,
    /// Стек свободных читающих соединений (round-robin по доступности).
    reads: Mutex<Vec<Connection>>,
    /// Приблизительное число конвертов во всех очередях — чтобы не делать
    /// `COUNT(*)` на каждом дропе. Точное значение восстанавливается при
    /// срабатывании потолка и при старте.
    message_count: AtomicI64,
    /// Приблизительный суммарный объём конвертов (байт).
    ///
    /// Нужен отдельно от [`Store::message_count`]: без него байтовый потолок
    /// проверялся бы только при срабатывании потолка ПО ЧИСЛУ, а с дефолтами
    /// (200 000 конвертов по 64 КиБ) это наступало бы лишь после ~12.8 ГБ —
    /// то есть лимит объёма был бы фактически мёртв.
    ///
    /// Счётчик намеренно приблизителен и «сверху»: вытеснения по лимиту очереди,
    /// `ack` и `sweep` его не уменьшают, поэтому он может завышать объём. Это
    /// безопасная сторона ошибки (уборка запускается чуть раньше, чем строго
    /// нужно), а [`Store::trim_global`] каждый раз пересчитывает оба счётчика
    /// точным запросом.
    message_bytes: AtomicI64,
    /// Приблизительный суммарный объём блобов вложений (байт), по тем же
    /// правилам, что [`Store::message_bytes`].
    ///
    /// Считается инкрементально именно потому, что точный запрос здесь ДОРОГ:
    /// `SUM(LENGTH(data))` по таблице блобов заставляет SQLite ходить по
    /// overflow-страницам многомегабайтных значений, и на каждой загрузке
    /// вложения это был бы проход по всему хранилищу вложений.
    blob_bytes: AtomicI64,
}

impl Store {
    /// Открывает/создаёт БД и применяет схему.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let write = Connection::open(path)?;
        configure(&write)?;
        write.execute_batch(SCHEMA)?;
        let mut reads = Vec::with_capacity(READ_CONNECTIONS);
        for _ in 0..READ_CONNECTIONS {
            let conn = Connection::open(path)?;
            configure(&conn)?;
            reads.push(conn);
        }
        let (count, bytes) = write.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM messages",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;
        let blob_bytes: i64 =
            write.query_row("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM blobs", [], |r| r.get(0))?;
        Ok(Store {
            write: Mutex::new(write),
            reads: Mutex::new(reads),
            message_count: AtomicI64::new(count),
            message_bytes: AtomicI64::new(bytes),
            blob_bytes: AtomicI64::new(blob_bytes),
        })
    }

    /// Открывает БД в памяти (для тестов). Читающих соединений нет: `:memory:`
    /// у каждого соединения своя — читаем через пишущее.
    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            write: Mutex::new(conn),
            reads: Mutex::new(Vec::new()),
            message_count: AtomicI64::new(0),
            message_bytes: AtomicI64::new(0),
            blob_bytes: AtomicI64::new(0),
        })
    }

    /// Выполняет читающий запрос на свободном соединении из пула; если пул пуст
    /// (все заняты либо режим `:memory:`) — на пишущем соединении.
    fn with_read<T>(&self, f: impl FnOnce(&Connection) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let borrowed = self.reads.lock().unwrap().pop();
        match borrowed {
            Some(conn) => {
                let result = f(&conn);
                self.reads.lock().unwrap().push(conn);
                result
            }
            None => f(&self.write.lock().unwrap()),
        }
    }

    /// Добавляет конверт в очередь mailbox и возвращает его порядковый номер.
    ///
    /// Вытеснение идёт на двух уровнях: старейшие сверх `max_queue` в этой
    /// очереди и — при превышении глобальных потолков — старейшие по всей БД.
    pub fn append(
        &self,
        mailbox: &str,
        data: &[u8],
        ts: i64,
        limits: &StoreLimits,
    ) -> anyhow::Result<i64> {
        let mut conn = self.write.lock().unwrap();
        let tx = conn.transaction()?;
        // Ошибку запроса НЕ глотаем: молчаливый откат на seq=1 мог бы переиспользовать
        // номер, который клиент уже подтвердил (ack), и потерять конверт.
        let next: i64 = tx
            .query_row(
                "SELECT next_seq FROM mailbox_seq WHERE mailbox = ?1",
                params![mailbox],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(1);
        tx.execute(
            "INSERT INTO mailbox_seq(mailbox, next_seq) VALUES(?1, ?2)
             ON CONFLICT(mailbox) DO UPDATE SET next_seq = ?2",
            params![mailbox, next + 1],
        )?;
        tx.execute(
            "INSERT INTO messages(mailbox, seq, data, ts) VALUES(?1, ?2, ?3, ?4)",
            params![mailbox, next, data, ts],
        )?;
        // Вытеснение старейших сверх лимита ОЧЕРЕДИ.
        let evicted_local = tx.execute(
            "DELETE FROM messages WHERE mailbox = ?1 AND seq <= (
                 SELECT seq FROM messages WHERE mailbox = ?1 ORDER BY seq DESC LIMIT 1 OFFSET ?2
             )",
            params![mailbox, limits.max_queue as i64],
        )?;
        tx.commit()?;

        let total = self
            .message_count
            .fetch_add(1 - evicted_local as i64, Ordering::Relaxed)
            + 1
            - evicted_local as i64;
        let total_bytes =
            self.message_bytes.fetch_add(data.len() as i64, Ordering::Relaxed) + data.len() as i64;
        // Уборку запускает превышение ЛЮБОГО из потолков: иначе лимит объёма
        // ждал бы, пока наберётся `max_total_messages` конвертов.
        if total > limits.max_total_messages || total_bytes > limits.max_total_bytes {
            self.trim_global(&mut conn, limits)?;
        }
        Ok(next)
    }

    /// Приводит БД к глобальным потолкам: удаляет самые старые конверты, пока
    /// число записей и суммарный объём не войдут в лимиты. Счётчик после этого
    /// пересчитывается точно.
    fn trim_global(&self, conn: &mut Connection, limits: &StoreLimits) -> anyhow::Result<()> {
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM messages WHERE rowid IN (
                 SELECT rowid FROM messages ORDER BY ts ASC, rowid ASC
                 LIMIT MAX(0, (SELECT COUNT(*) FROM messages) - ?1)
             )",
            params![limits.max_total_messages],
        )?;
        // Объём: удаляем старейшие, пока суммарный размер выше потолка.
        loop {
            let bytes: i64 = tx
                .query_row("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM messages", [], |r| {
                    r.get(0)
                })?;
            if bytes <= limits.max_total_bytes {
                break;
            }
            let removed = tx.execute(
                "DELETE FROM messages WHERE rowid IN (
                     SELECT rowid FROM messages ORDER BY ts ASC, rowid ASC LIMIT 128
                 )",
                [],
            )?;
            if removed == 0 {
                break;
            }
        }
        // Оба счётчика пересчитываем ТОЧНО: приблизительные значения могли
        // разойтись с БД из-за вытеснений по лимиту очереди, `ack` и `sweep`.
        let (exact, exact_bytes) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM messages",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;
        tx.commit()?;
        self.message_count.store(exact, Ordering::Relaxed);
        self.message_bytes.store(exact_bytes, Ordering::Relaxed);
        tracing::warn!(
            remaining = exact,
            remaining_bytes = exact_bytes,
            "глобальный потолок хранения: вытеснены самые старые конверты"
        );
        Ok(())
    }

    /// Возвращает сообщения с `seq > after` (по возрастанию), не более `limit`.
    pub fn fetch_after(
        &self,
        mailbox: &str,
        after: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<StoredItem>> {
        self.with_read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT seq, data, ts FROM messages WHERE mailbox = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![mailbox, after, limit as i64], |r| {
                Ok(StoredItem { seq: r.get(0)?, data: r.get(1)?, ts: r.get(2)? })
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// Удаляет подтверждённые (обработанные клиентом) сообщения `seq <= upto`.
    pub fn ack(&self, mailbox: &str, upto: i64) -> anyhow::Result<usize> {
        let conn = self.write.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM messages WHERE mailbox = ?1 AND seq <= ?2",
            params![mailbox, upto],
        )?;
        self.message_count.fetch_sub(n as i64, Ordering::Relaxed);
        Ok(n)
    }

    /// Удаляет данные старше `cutoff_ts` (жёсткий потолок хранения §7.3).
    /// Записи каталога и заявки алиасов живут по СВОИМ срокам (`expires_at`),
    /// потому что их назначение — быть доступными долго.
    pub fn sweep(&self, cutoff_ts: i64, now_ts: i64) -> anyhow::Result<usize> {
        let conn = self.write.lock().unwrap();
        let n = conn.execute("DELETE FROM messages WHERE ts < ?1", params![cutoff_ts])?;
        self.message_count.fetch_sub(n as i64, Ordering::Relaxed);
        // Заодно чистим осиротевшие prekeys и блобы вложений старше TTL (§14.4).
        conn.execute("DELETE FROM prekeys WHERE ts < ?1", params![cutoff_ts])?;
        conn.execute("DELETE FROM blobs WHERE ts < ?1", params![cutoff_ts])?;
        // Просроченные записи каталога/алиасов (срок задаёт сам владелец).
        conn.execute("DELETE FROM directory WHERE expires_at < ?1", params![now_ts])?;
        conn.execute("DELETE FROM aliases WHERE expires_at < ?1", params![now_ts])?;
        Ok(n)
    }

    /// Сохраняет зашифрованный блоб вложения (§14.4) под опаковым `id`.
    ///
    /// Вытеснение идёт по ДВУМ потолкам, как у конвертов: по числу блобов
    /// (`max_blobs`) и по суммарному объёму (`max_blob_bytes`). Потолка по числу
    /// одного недостаточно — он допускает `max_blobs × blob_max_bytes` байт на
    /// диске (с дефолтами это 24 ГиБ), то есть вложения были бы единственным
    /// способом переполнить диск, зная лишь onion-адрес.
    pub fn put_blob(
        &self,
        id: &str,
        data: &[u8],
        ts: i64,
        limits: &StoreLimits,
    ) -> anyhow::Result<()> {
        let mut conn = self.write.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(id, data, ts) VALUES(?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET data = ?2, ts = ?3",
            params![id, data, ts],
        )?;
        // Вытеснение старейших сверх лимита (по времени загрузки).
        conn.execute(
            "DELETE FROM blobs WHERE id IN (
                 SELECT id FROM blobs ORDER BY ts DESC, id DESC LIMIT -1 OFFSET ?1
             )",
            params![limits.max_blobs as i64],
        )?;
        let added = data.len() as i64;
        let total = self.blob_bytes.fetch_add(added, Ordering::Relaxed) + added;
        if total > limits.max_blob_bytes {
            self.trim_blobs(&mut conn, limits)?;
        }
        Ok(())
    }

    /// Приводит хранилище блобов к байтовому потолку, удаляя самые старые.
    ///
    /// Счётчик после уборки пересчитывается ТОЧНО: приблизительное значение
    /// расходится с БД из-за `delete_blob` (получатель подтверждает приём) и
    /// `sweep` (TTL) — они его не уменьшают, чтобы не платить за пересчёт на
    /// каждом скачивании вложения.
    fn trim_blobs(&self, conn: &mut Connection, limits: &StoreLimits) -> anyhow::Result<()> {
        let tx = conn.transaction()?;
        loop {
            let bytes: i64 =
                tx.query_row("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM blobs", [], |r| r.get(0))?;
            if bytes <= limits.max_blob_bytes {
                break;
            }
            // Удаляем небольшими партиями: блобы крупные, и одна итерация обычно
            // уже приводит объём в норму. Нулевой результат означает пустую
            // таблицу (один блоб больше всего потолка) — иначе цикл был бы вечным.
            let removed = tx.execute(
                "DELETE FROM blobs WHERE id IN (
                     SELECT id FROM blobs ORDER BY ts ASC, id ASC LIMIT 8
                 )",
                [],
            )?;
            if removed == 0 {
                break;
            }
        }
        let exact: i64 =
            tx.query_row("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM blobs", [], |r| r.get(0))?;
        tx.commit()?;
        self.blob_bytes.store(exact, Ordering::Relaxed);
        tracing::warn!(
            remaining_bytes = exact,
            "байтовый потолок блобов: вытеснены самые старые вложения"
        );
        Ok(())
    }

    /// Возвращает зашифрованный блоб по `id` (или `None`, если нет/просрочен).
    pub fn get_blob(&self, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.with_read(|conn| {
            Ok(conn
                .query_row("SELECT data FROM blobs WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?)
        })
    }

    /// Удаляет блоб по `id` (получатель подтверждает получение — §7.3/§10.9).
    pub fn delete_blob(&self, id: &str) -> anyhow::Result<usize> {
        let conn = self.write.lock().unwrap();
        let n = conn.execute("DELETE FROM blobs WHERE id = ?1", params![id])?;
        Ok(n)
    }

    /// Публикует публичный prekey-бандл (§7.6, опциональный путь keys.overSignal).
    pub fn put_prekey(&self, id: &str, bundle: &str, ts: i64) -> anyhow::Result<()> {
        let conn = self.write.lock().unwrap();
        conn.execute(
            "INSERT INTO prekeys(id, bundle, ts) VALUES(?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET bundle = ?2, ts = ?3",
            params![id, bundle, ts],
        )?;
        Ok(())
    }

    /// Возвращает опубликованный prekey-бандл по id (или `None`).
    pub fn get_prekey(&self, id: &str) -> anyhow::Result<Option<String>> {
        self.with_read(|conn| {
            Ok(conn
                .query_row("SELECT bundle FROM prekeys WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?)
        })
    }

    // --- Каталог обнаружения (удалённое добавление контакта) ----------------

    /// Публикует ЗАПЕЧАТАННУЮ запись каталога под опаковым `index`.
    ///
    /// Сервер не может её прочитать (AEAD на ключе, выведенном из тега
    /// обнаружения, которого у сервера нет) и не знает, кому она принадлежит.
    /// Перезапись под тем же индексом разрешена: обновить запись может только
    /// тот, кто знает тег (256 бит) — то есть сам владелец.
    pub fn put_directory(
        &self,
        index: &str,
        data: &[u8],
        ts: i64,
        expires_at: i64,
        limits: &StoreLimits,
    ) -> anyhow::Result<()> {
        let conn = self.write.lock().unwrap();
        conn.execute(
            "INSERT INTO directory(idx, data, ts, expires_at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(idx) DO UPDATE SET data = ?2, ts = ?3, expires_at = ?4",
            params![index, data, ts, expires_at],
        )?;
        conn.execute(
            "DELETE FROM directory WHERE idx IN (
                 SELECT idx FROM directory ORDER BY ts DESC, idx DESC LIMIT -1 OFFSET ?1
             )",
            params![limits.max_directory],
        )?;
        Ok(())
    }

    /// Возвращает запечатанную запись каталога (или `None`, если нет/просрочена).
    pub fn get_directory(&self, index: &str, now_ts: i64) -> anyhow::Result<Option<Vec<u8>>> {
        self.with_read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT data FROM directory WHERE idx = ?1 AND expires_at >= ?2",
                    params![index, now_ts],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// Удаляет запись каталога (владелец «снялся с публикации»). Идемпотентно.
    pub fn delete_directory(&self, index: &str) -> anyhow::Result<usize> {
        let conn = self.write.lock().unwrap();
        Ok(conn.execute("DELETE FROM directory WHERE idx = ?1", params![index])?)
    }

    // --- Публичные алиасы (`@ник`) ------------------------------------------

    /// Состояние действующей (непросроченной) заявки на алиас, если она есть.
    /// Нужно, чтобы разрешить обновление ТОЛЬКО владельцу ключа (иначе алиас
    /// угоняется простой перезаписью) и только более свежей заявкой.
    pub fn alias_guard(&self, index: &str, now_ts: i64) -> anyhow::Result<Option<AliasGuard>> {
        self.with_read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT ed25519, issued_at_ms FROM aliases WHERE idx = ?1 AND expires_at >= ?2",
                    params![index, now_ts],
                    |r| {
                        Ok(AliasGuard {
                            ed25519_hex: r.get(0)?,
                            issued_at_ms: r.get(1)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    /// Записывает (или продлевает) заявку на алиас. Вызывающий ОБЯЗАН заранее
    /// проверить подпись и владение ([`crate::directory::verify_alias_claim`]).
    #[allow(clippy::too_many_arguments)]
    pub fn put_alias(
        &self,
        index: &str,
        claim_b64: &str,
        sig_b64: &str,
        ed25519_hex: &str,
        issued_at_ms: i64,
        ts: i64,
        expires_at: i64,
        limits: &StoreLimits,
    ) -> anyhow::Result<()> {
        let conn = self.write.lock().unwrap();
        conn.execute(
            "INSERT INTO aliases(idx, claim, sig, ed25519, issued_at_ms, ts, expires_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(idx) DO UPDATE SET claim = ?2, sig = ?3, ed25519 = ?4,
                                            issued_at_ms = ?5, ts = ?6, expires_at = ?7",
            params![index, claim_b64, sig_b64, ed25519_hex, issued_at_ms, ts, expires_at],
        )?;
        // Потолок: сначала выбрасываем просроченные, затем самые старые.
        conn.execute("DELETE FROM aliases WHERE expires_at < ?1", params![ts])?;
        conn.execute(
            "DELETE FROM aliases WHERE idx IN (
                 SELECT idx FROM aliases ORDER BY ts DESC, idx DESC LIMIT -1 OFFSET ?1
             )",
            params![limits.max_aliases],
        )?;
        Ok(())
    }

    /// Возвращает подписанную заявку на алиас (или `None`, если нет/просрочена).
    pub fn get_alias(&self, index: &str, now_ts: i64) -> anyhow::Result<Option<AliasClaim>> {
        self.with_read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT claim, sig FROM aliases WHERE idx = ?1 AND expires_at >= ?2",
                    params![index, now_ts],
                    |r| Ok(AliasClaim { claim_b64: r.get(0)?, sig_b64: r.get(1)? }),
                )
                .optional()?)
        })
    }

    /// Число сообщений во всех очередях (для healthcheck; не раскрывает контент).
    pub fn queued(&self) -> anyhow::Result<i64> {
        self.with_read(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?)
        })
    }
}

/// Общие для всех соединений настройки: WAL (параллельные читатели), разумный
/// таймаут на блокировку писателя вместо мгновенного `SQLITE_BUSY`.
fn configure(conn: &Connection) -> anyhow::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    // Писатель один, но читателей из пула несколько: ждём освобождения блокировки
    // вместо мгновенного SQLITE_BUSY (иначе long-poll падал бы под нагрузкой).
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
    mailbox TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    data    BLOB NOT NULL,
    ts      INTEGER NOT NULL,
    PRIMARY KEY (mailbox, seq)
);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
CREATE TABLE IF NOT EXISTS mailbox_seq (
    mailbox  TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS prekeys (
    id     TEXT PRIMARY KEY,
    bundle TEXT NOT NULL,
    ts     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS blobs (
    id   TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    ts   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blobs_ts ON blobs(ts);
CREATE TABLE IF NOT EXISTS directory (
    idx        TEXT PRIMARY KEY,
    data       BLOB NOT NULL,
    ts         INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_directory_expires ON directory(expires_at);
CREATE TABLE IF NOT EXISTS aliases (
    idx          TEXT PRIMARY KEY,
    claim        TEXT NOT NULL,
    sig          TEXT NOT NULL,
    ed25519      TEXT NOT NULL,
    issued_at_ms INTEGER NOT NULL DEFAULT 0,
    ts           INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aliases_expires ON aliases(expires_at);
";

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_queue: usize) -> StoreLimits {
        StoreLimits {
            max_queue,
            max_total_messages: 1_000_000,
            max_total_bytes: 1 << 30,
            max_blobs: 1_000,
            max_blob_bytes: 1 << 30,
            max_directory: 1_000,
            max_aliases: 1_000,
        }
    }

    #[test]
    fn append_fetch_ack_roundtrip() {
        let s = Store::open_in_memory().unwrap();
        let l = limits(1000);
        let seq1 = s.append("mbox", b"one", 100, &l).unwrap();
        let seq2 = s.append("mbox", b"two", 200, &l).unwrap();
        assert_eq!((seq1, seq2), (1, 2));

        let items = s.fetch_after("mbox", 0, 100).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].data, b"one");
        assert_eq!(items[1].seq, 2);

        // Изоляция очередей: чужой mailbox пуст.
        assert!(s.fetch_after("other", 0, 100).unwrap().is_empty());

        // after=1 → только второе.
        let tail = s.fetch_after("mbox", 1, 100).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].data, b"two");

        // ack удаляет обработанное.
        assert_eq!(s.ack("mbox", 1).unwrap(), 1);
        assert_eq!(s.fetch_after("mbox", 0, 100).unwrap().len(), 1);
    }

    #[test]
    fn queue_cap_evicts_oldest() {
        let s = Store::open_in_memory().unwrap();
        let l = limits(3);
        for i in 0..5 {
            s.append("m", format!("msg{i}").as_bytes(), i, &l).unwrap();
        }
        let items = s.fetch_after("m", 0, 100).unwrap();
        assert_eq!(items.len(), 3, "очередь ограничена max_queue=3");
        // Остались самые свежие.
        assert_eq!(items.last().unwrap().data, b"msg4");
    }

    /// Регрессия на DoS диска: per-mailbox лимит не спасал от дропов в
    /// НЕОГРАНИЧЕННОЕ число новых ящиков — теперь работает глобальный потолок.
    #[test]
    fn global_message_cap_evicts_across_mailboxes() {
        let s = Store::open_in_memory().unwrap();
        let l = StoreLimits { max_total_messages: 10, ..limits(1000) };
        for i in 0..50i64 {
            s.append(&format!("mbox{i}"), b"spam", i, &l).unwrap();
        }
        let total = s.queued().unwrap();
        assert!(total <= 10, "глобальный потолок не сработал: {total} конвертов");
        // Уцелеть должны самые свежие.
        assert!(!s.fetch_after("mbox49", 0, 10).unwrap().is_empty());
    }

    /// Суммарный объём конвертов в БД (для проверки байтового потолка).
    #[cfg(test)]
    fn total_bytes(s: &Store) -> i64 {
        s.with_read(|conn| {
            Ok(conn.query_row("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM messages", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap()
    }

    /// Регрессия: байтовый потолок обязан срабатывать САМ, не дожидаясь потолка
    /// по числу конвертов. Раньше он проверялся только внутри `trim_global`,
    /// который запускался лишь по превышению `max_total_messages` — с дефолтами
    /// (200 000 × 64 КиБ) это означало ~12.8 ГБ, то есть лимит объёма был мёртв.
    #[test]
    fn global_byte_cap_triggers_without_message_cap() {
        let s = Store::open_in_memory().unwrap();
        // Потолок по числу заведомо недостижим — работать должен именно байтовый.
        let l = StoreLimits { max_total_messages: 1_000_000, max_total_bytes: 5_000, ..limits(1000) };
        let payload = vec![0u8; 1_000];
        for i in 0..50i64 {
            s.append(&format!("m{i}"), &payload, i, &l).unwrap();
        }
        let bytes = total_bytes(&s);
        assert!(
            bytes <= l.max_total_bytes,
            "байтовый потолок не сработал: {bytes} Б при лимите {} Б",
            l.max_total_bytes,
        );
        // Уцелеть должны САМЫЕ СВЕЖИЕ конверты, а не случайные.
        assert!(!s.fetch_after("m49", 0, 10).unwrap().is_empty());
    }

    /// Вырожденный случай: ОДИН конверт больше всего потолка. Важно, что цикл
    /// вытеснения завершается (а не крутится вечно) и БД остаётся пригодной.
    #[test]
    fn global_byte_cap_terminates_when_single_item_exceeds_cap() {
        let s = Store::open_in_memory().unwrap();
        let l = StoreLimits { max_total_messages: 5, max_total_bytes: 64, ..limits(1000) };
        let big = vec![0u8; 100];
        for i in 0..10i64 {
            s.append(&format!("m{i}"), &big, i, &l).unwrap();
        }
        // Каждый конверт (100 Б) сам превышает потолок 64 Б, поэтому после
        // уборки остаётся не больше одного — только что добавленный.
        let queued = s.queued().unwrap();
        assert!(queued <= 1, "ожидалось ≤1 конверта, получено {queued}");
    }

    #[test]
    fn sweep_removes_expired() {
        let s = Store::open_in_memory().unwrap();
        let l = limits(1000);
        s.append("m", b"old", 10, &l).unwrap();
        s.append("m", b"new", 10_000, &l).unwrap();
        let removed = s.sweep(5_000, 10_000).unwrap();
        assert_eq!(removed, 1);
        let items = s.fetch_after("m", 0, 100).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].data, b"new");
        assert_eq!(s.queued().unwrap(), 1, "счётчик конвертов должен сойтись");
    }

    #[test]
    fn blob_put_get_delete_roundtrip() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.get_blob("obj1").unwrap().is_none());
        s.put_blob("obj1", b"ciphertext-blob", 100, &limits(1000)).unwrap();
        assert_eq!(s.get_blob("obj1").unwrap().unwrap(), b"ciphertext-blob");
        // Перезапись обновляет содержимое.
        s.put_blob("obj1", b"updated", 200, &limits(1000)).unwrap();
        assert_eq!(s.get_blob("obj1").unwrap().unwrap(), b"updated");
        // Удаление получателем.
        assert_eq!(s.delete_blob("obj1").unwrap(), 1);
        assert!(s.get_blob("obj1").unwrap().is_none());
    }

    #[test]
    fn blob_cap_evicts_oldest() {
        let s = Store::open_in_memory().unwrap();
        for i in 0..5 {
            s.put_blob(&format!("obj{i}"), format!("blob{i}").as_bytes(), i, &StoreLimits { max_blobs: 3, ..limits(1000) }).unwrap();
        }
        // Осталось не более 3 блобов; самый старый (obj0) вытеснен.
        assert!(s.get_blob("obj0").unwrap().is_none());
        assert!(s.get_blob("obj4").unwrap().is_some());
    }

    /// Суммарный объём блобов в БД (для проверки байтового потолка).
    #[cfg(test)]
    fn total_blob_bytes(s: &Store) -> i64 {
        s.with_read(|conn| {
            Ok(conn.query_row("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM blobs", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap()
    }

    /// Регрессия на DoS диска через вложения: потолок ПО ЧИСЛУ блобов допускал
    /// `max_blobs × blob_max_bytes` байт (с дефолтами 2000 × 12 МиБ = 24 ГиБ),
    /// то есть был единственной дырой в защите диска — у конвертов байтовый
    /// потолок есть, а у блобов не было.
    #[test]
    fn blob_byte_cap_triggers_without_count_cap() {
        let s = Store::open_in_memory().unwrap();
        // Потолок по числу заведомо недостижим — работать должен именно байтовый.
        let l = StoreLimits { max_blobs: 1_000_000, max_blob_bytes: 5_000, ..limits(1000) };
        let payload = vec![7u8; 1_000];
        for i in 0..50i64 {
            s.put_blob(&format!("obj{i:03}"), &payload, i, &l).unwrap();
        }
        let bytes = total_blob_bytes(&s);
        assert!(
            bytes <= l.max_blob_bytes,
            "байтовый потолок блобов не сработал: {bytes} Б при лимите {} Б",
            l.max_blob_bytes,
        );
        // Уцелеть должны САМЫЕ СВЕЖИЕ вложения: получатель качает последнее.
        assert!(s.get_blob("obj049").unwrap().is_some());
        assert!(s.get_blob("obj000").unwrap().is_none());
    }

    /// Вырожденный случай: ОДИН блоб больше всего потолка. Важно, что цикл
    /// вытеснения завершается, а не крутится вечно под блокировкой писателя.
    #[test]
    fn blob_byte_cap_terminates_when_single_blob_exceeds_cap() {
        let s = Store::open_in_memory().unwrap();
        let l = StoreLimits { max_blobs: 100, max_blob_bytes: 64, ..limits(1000) };
        let big = vec![0u8; 500];
        for i in 0..10i64 {
            s.put_blob(&format!("obj{i}"), &big, i, &l).unwrap();
        }
        // Каждый блоб сам превышает потолок, поэтому после уборки таблица либо
        // пуста, либо содержит один только что добавленный блоб.
        assert!(total_blob_bytes(&s) <= 500, "уборка не сошлась");
    }

    /// Счётчик объёма блобов приблизителен и «сверху», но после уборки он обязан
    /// совпасть с БД — иначе следующий `put_blob` запускал бы уборку вечно
    /// (счётчик выше потолка) либо не запускал её вовсе (счётчик ниже реального).
    #[test]
    fn blob_byte_counter_reconciles_after_trim() {
        let s = Store::open_in_memory().unwrap();
        let l = StoreLimits { max_blobs: 1_000, max_blob_bytes: 3_000, ..limits(1000) };
        for i in 0..20i64 {
            s.put_blob(&format!("obj{i:02}"), &vec![1u8; 500], i, &l).unwrap();
        }
        // Удаления получателем счётчик не уменьшают — это допустимая
        // переоценка; после следующей уборки он обязан сойтись точно.
        s.delete_blob("obj19").unwrap();
        for i in 20..30i64 {
            s.put_blob(&format!("obj{i:02}"), &vec![1u8; 500], i, &l).unwrap();
        }
        assert_eq!(
            s.blob_bytes.load(Ordering::Relaxed),
            total_blob_bytes(&s),
            "счётчик объёма блобов разошёлся с БД",
        );
    }

    #[test]
    fn sweep_removes_expired_blobs() {
        let s = Store::open_in_memory().unwrap();
        s.put_blob("old", b"x", 10, &limits(1000)).unwrap();
        s.put_blob("new", b"y", 10_000, &limits(1000)).unwrap();
        s.sweep(5_000, 10_000).unwrap();
        assert!(s.get_blob("old").unwrap().is_none());
        assert!(s.get_blob("new").unwrap().is_some());
    }

    #[test]
    fn prekey_publish_and_fetch() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.get_prekey("acct").unwrap().is_none());
        s.put_prekey("acct", "{\"bundle\":true}", 1).unwrap();
        assert_eq!(s.get_prekey("acct").unwrap().unwrap(), "{\"bundle\":true}");
        // Перепубликация обновляет.
        s.put_prekey("acct", "{\"bundle\":2}", 2).unwrap();
        assert_eq!(s.get_prekey("acct").unwrap().unwrap(), "{\"bundle\":2}");
    }

    #[test]
    fn directory_put_get_delete_and_expiry() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.get_directory("idx1", 100).unwrap().is_none());
        s.put_directory("idx1", b"sealed-record", 100, 1_000, &limits(1000)).unwrap();
        assert_eq!(s.get_directory("idx1", 500).unwrap().unwrap(), b"sealed-record");
        // Перезапись владельцем (он знает тег) обновляет запись.
        s.put_directory("idx1", b"updated", 200, 2_000, &limits(1000)).unwrap();
        assert_eq!(s.get_directory("idx1", 500).unwrap().unwrap(), b"updated");
        // После expires_at запись не отдаётся, даже если ещё не подметена.
        assert!(s.get_directory("idx1", 2_001).unwrap().is_none());
        // Явное снятие с публикации.
        assert_eq!(s.delete_directory("idx1").unwrap(), 1);
        assert!(s.get_directory("idx1", 500).unwrap().is_none());
    }

    #[test]
    fn directory_cap_evicts_oldest() {
        let s = Store::open_in_memory().unwrap();
        for i in 0..6i64 {
            s.put_directory(&format!("idx{i}"), b"rec", i, 10_000, &StoreLimits { max_directory: 3, ..limits(1000) }).unwrap();
        }
        assert!(s.get_directory("idx0", 1).unwrap().is_none());
        assert!(s.get_directory("idx5", 1).unwrap().is_some());
    }

    #[test]
    fn alias_guard_tracks_key_issued_at_and_expiry() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.alias_guard("a1", 100).unwrap().is_none());
        let key = "aa".repeat(32);
        s.put_alias("a1", "claim-b64", "sig-b64", &key, 100_000, 100, 1_000, &limits(1000)).unwrap();
        let guard = s.alias_guard("a1", 500).unwrap().unwrap();
        assert_eq!(guard.ed25519_hex, key);
        assert_eq!(guard.issued_at_ms, 100_000);
        let claim = s.get_alias("a1", 500).unwrap().unwrap();
        assert_eq!(claim.claim_b64, "claim-b64");
        assert_eq!(claim.sig_b64, "sig-b64");
        // Просроченная заявка не считается занятой — алиас можно перезанять.
        assert!(s.alias_guard("a1", 1_001).unwrap().is_none());
        assert!(s.get_alias("a1", 1_001).unwrap().is_none());
    }

    #[test]
    fn sweep_removes_expired_directory_and_aliases() {
        let s = Store::open_in_memory().unwrap();
        s.put_directory("old", b"r", 10, 100, &limits(1000)).unwrap();
        s.put_directory("new", b"r", 10, 10_000, &limits(1000)).unwrap();
        s.put_alias("old", "c", "s", "ff", 1, 10, 100, &limits(1000)).unwrap();
        s.put_alias("new", "c", "s", "ff", 1, 10, 10_000, &limits(1000)).unwrap();
        s.sweep(0, 5_000).unwrap();
        assert!(s.get_directory("old", 5_000).unwrap().is_none());
        assert!(s.get_directory("new", 5_000).unwrap().is_some());
        assert!(s.get_alias("old", 5_000).unwrap().is_none());
        assert!(s.get_alias("new", 5_000).unwrap().is_some());
    }
}

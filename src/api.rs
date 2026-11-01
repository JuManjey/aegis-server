//! HTTP API релея (§7.6/§12.2). Публикуется как Onion Service v3.
//!
//! Zero-trust к серверу (§10.9): сервер оперирует только непрозрачными
//! идентификаторами mailbox (256-бит, выведены клиентом из PSK через HKDF) и
//! зашифрованными конвертами. Никакой аутентификации по личности — знание
//! mailbox-id (256 бит энтропии) само по себе является capability; личность,
//! связь «кто-кому» и содержимое серверу недоступны.
//!
//! Маршруты:
//!   GET  /v1/health                — состояние сервиса (для healthcheck).
//!   POST /v1/mailbox/{id}          — положить конверт в очередь (анонимный дроп).
//!   GET  /v1/mailbox/{id}?after&wait — long-poll приём (§12.2).
//!   POST /v1/mailbox/{id}/ack      — подтвердить обработку (удалить ≤ upto).
//!   PUT  /v1/prekeys/{id}          — опубликовать публичный prekey-бандл (§7.6).
//!   GET  /v1/prekeys/{id}          — получить prekey-бандл (путь keys.overSignal).
//!   PUT  /v1/blob/{id}             — загрузить зашифрованный блоб вложения (§14.4).
//!   GET  /v1/blob/{id}             — скачать блоб вложения (octet-stream).
//!   DELETE /v1/blob/{id}           — удалить блоб (получатель подтверждает приём).
//!   GET  /v1/turn                  — эфемерные TURN-креды для медиа звонков (§7.5).
//!   GET  /v1/config                — подписанный офлайн адрес релея (авто-обнаружение, §12.2).
//!   GET  /v1/params                — параметры каталога и сложность PoW для клиента.
//!   PUT  /v1/directory/{index}     — опубликовать ЗАПЕЧАТАННУЮ запись каталога.
//!   GET  /v1/directory/{index}     — получить запечатанную запись каталога.
//!   DELETE /v1/directory/{index}   — снять запись с публикации.
//!   PUT  /v1/alias/{index}         — занять/продлить ПУБЛИЧНЫЙ алиас (`@ник`).
//!   GET  /v1/alias/{index}         — получить подписанную заявку на алиас.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Notify;

use crate::config::Config;
use crate::directory::{self, ClaimError};
use crate::pow;
use crate::store::Store;
use crate::turn;

/// Заголовок с решением proof-of-work на публичных маршрутах алиасов.
const POW_HEADER: &str = "x-aegis-pow";

/// Общее состояние приложения.
pub struct AppState {
    pub store: Store,
    pub cfg: Config,
    /// Пробуждатели long-poll по mailbox (лениво создаются на первое ожидание).
    notifiers: Mutex<HashMap<String, Arc<Notify>>>,
}

impl AppState {
    pub fn new(store: Store, cfg: Config) -> Self {
        AppState { store, cfg, notifiers: Mutex::new(HashMap::new()) }
    }

    /// Пробуждатель ящика для ожидающего long-poll.
    ///
    /// Возвращаемый `Arc` удерживает запись живой на время ожидания;
    /// освобождение делает [`AppState::release_notifier`]. Без этого карта
    /// росла безвозвратно — по записи на КАЖДЫЙ когда-либо опрошенный ящик, а
    /// ящиков теперь по одному на (контакт × устройство) плюс приглашения.
    fn notifier(&self, id: &str) -> Arc<Notify> {
        let mut map = self.notifiers.lock().unwrap();
        map.entry(id.to_string()).or_insert_with(|| Arc::new(Notify::new())).clone()
    }

    /// Убирает пробуждатель, если этот ожидающий был последним.
    ///
    /// `strong_count <= 2` — ссылка в карте плюс наша: значит других ожидающих
    /// нет и запись можно удалить. Проверка идёт под тем же `Mutex`, что и
    /// вставка в [`AppState::notifier`], поэтому гонки «удалили запись, пока
    /// новый ожидающий её клонировал» не возникает. Потерять пробуждение тоже
    /// нельзя: после освобождения [`poll`] либо возвращает ответ, либо заново
    /// регистрирует интерес и ПЕРЕЧИТЫВАЕТ очередь.
    fn release_notifier(&self, id: &str, held: &Arc<Notify>) {
        let mut map = self.notifiers.lock().unwrap();
        if Arc::strong_count(held) <= 2 {
            map.remove(id);
        }
    }

    fn wake(&self, id: &str) {
        // Будим только если кто-то ждёт этот mailbox (иначе запись не создаём —
        // чтобы карта не росла от анонимных дропов в неслушаемые ящики).
        if let Some(n) = self.notifiers.lock().unwrap().get(id) {
            n.notify_waiters();
        }
    }

    /// Текущее число живых пробуждателей. Нужно регрессионному тесту на утечку
    /// карты `notifiers` — в проде не используется, поэтому только под `test`.
    #[cfg(test)]
    pub fn notifier_count(&self) -> usize {
        self.notifiers.lock().unwrap().len()
    }
}

pub type Shared = Arc<AppState>;

/// Собирает роутер приложения.
pub fn router(state: Shared) -> Router {
    let max_body = state.cfg.max_body;
    let blob_max = state.cfg.blob_max_bytes;

    // Загрузка блоба вложения (§14.4) — отдельный (больший) лимит тела, чтобы
    // не поднимать лимит для остальных маршрутов (компактных конвертов mailbox).
    let blob_upload = Router::new()
        .route("/v1/blob/{id}", put(put_blob))
        .layer(DefaultBodyLimit::max(blob_max));

    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/params", get(params))
        .route("/v1/mailbox/{id}", post(drop_message).get(poll))
        .route("/v1/mailbox/{id}/ack", post(ack))
        .route("/v1/prekeys/{id}", put(put_prekey).get(get_prekey))
        .route("/v1/blob/{id}", get(get_blob).delete(delete_blob))
        .route(
            "/v1/directory/{index}",
            put(put_directory).get(get_directory).delete(delete_directory),
        )
        .route("/v1/alias/{index}", put(put_alias).get(get_alias))
        .route("/v1/turn", get(turn_credentials))
        .route("/v1/config", get(server_config))
        .layer(DefaultBodyLimit::max(max_body))
        .merge(blob_upload)
        .with_state(state)
}

// --- Обработчики ------------------------------------------------------------

async fn health(State(st): State<Shared>) -> Json<serde_json::Value> {
    let queued = st.store.queued().unwrap_or(-1);
    Json(json!({
        "status": "ok",
        "service": "aegis-relay",
        "version": env!("CARGO_PKG_VERSION"),
        "queued": queued,
    }))
}

async fn drop_message(
    Path(id): Path<String>,
    State(st): State<Shared>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_id(&id)?;
    if body.is_empty() {
        return Err(ApiError::bad_request("пустое тело"));
    }
    let ts = now_secs();
    let seq = st
        .store
        .append(&id, &body, ts, &st.cfg.store_limits())
        .map_err(ApiError::internal)?;
    st.wake(&id);
    Ok(Json(json!({ "seq": seq })))
}

#[derive(Deserialize)]
struct PollQuery {
    after: Option<i64>,
    wait: Option<u64>,
}

async fn poll(
    Path(id): Path<String>,
    Query(q): Query<PollQuery>,
    State(st): State<Shared>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_id(&id)?;
    let after = q.after.unwrap_or(0).max(0);
    let wait = q.wait.unwrap_or(0).min(st.cfg.max_wait_secs);
    let deadline = Instant::now() + Duration::from_secs(wait);

    loop {
        // Регистрируем интерес ДО чтения из БД, чтобы не потерять пробуждение
        // от конкурентного дропа (tokio Notified::enable, tokio ≥ 1.x).
        let notify = st.notifier(&id);
        let outcome = {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let items = st.store.fetch_after(&id, after, st.cfg.poll_limit);
            let now = Instant::now();
            match items {
                Err(e) => Some(Err(e)),
                Ok(items) if !items.is_empty() || wait == 0 || now >= deadline => {
                    Some(Ok(items))
                }
                Ok(_) => {
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = tokio::time::sleep(deadline - now) => {}
                    }
                    None
                }
            }
        };
        // Освобождаем пробуждатель на КАЖДОМ выходе из итерации (включая ошибку
        // БД и таймаут), иначе карта росла бы безвозвратно — по записи на каждый
        // когда-либо опрошенный ящик.
        st.release_notifier(&id, &notify);

        let Some(result) = outcome else { continue };
        let items = result.map_err(ApiError::internal)?;
        let next = items.last().map(|i| i.seq).unwrap_or(after);
        let out: Vec<_> = items
            .iter()
            .map(|it| {
                json!({
                    "seq": it.seq,
                    "dataB64": base64::engine::general_purpose::STANDARD.encode(&it.data),
                    "ts": it.ts,
                })
            })
            .collect();
        return Ok(Json(json!({ "items": out, "next": next })));
    }
}

#[derive(Deserialize)]
struct AckBody {
    upto: i64,
}

async fn ack(
    Path(id): Path<String>,
    State(st): State<Shared>,
    Json(b): Json<AckBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_id(&id)?;
    let n = st.store.ack(&id, b.upto).map_err(ApiError::internal)?;
    Ok(Json(json!({ "acked": n })))
}

async fn put_prekey(
    Path(id): Path<String>,
    State(st): State<Shared>,
    body: String,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_id(&id)?;
    if body.is_empty() {
        return Err(ApiError::bad_request("пустой бандл"));
    }
    // Сервер не разбирает бандл — хранит как непрозрачную строку (§7.6).
    st.store.put_prekey(&id, &body, now_secs()).map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_prekey(Path(id): Path<String>, State(st): State<Shared>) -> Result<Response, ApiError> {
    validate_id(&id)?;
    match st.store.get_prekey(&id).map_err(ApiError::internal)? {
        Some(bundle) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bundle,
        )
            .into_response()),
        None => Err(ApiError::NotFound),
    }
}

/// `PUT /v1/blob/{id}` — загружает зашифрованный блоб вложения (§14.4). `id` —
/// опаковый 256-бит идентификатор, сгенерированный клиентом (capability, как
/// mailbox). Тело — непрозрачный шифртекст (каскад слоя A на случайном ключе);
/// сервер его не разбирает и не связывает с личностью/перепиской (§10.9).
async fn put_blob(
    Path(id): Path<String>,
    State(st): State<Shared>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_id(&id)?;
    if body.is_empty() {
        return Err(ApiError::bad_request("пустой блоб"));
    }
    st.store
        .put_blob(&id, &body, now_secs(), &st.cfg.store_limits())
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

/// `GET /v1/blob/{id}` — отдаёт блоб вложения как `application/octet-stream`
/// либо 404, если его нет (не загружен / просрочен по TTL / уже удалён).
async fn get_blob(Path(id): Path<String>, State(st): State<Shared>) -> Result<Response, ApiError> {
    validate_id(&id)?;
    match st.store.get_blob(&id).map_err(ApiError::internal)? {
        Some(data) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response()),
        None => Err(ApiError::NotFound),
    }
}

/// `DELETE /v1/blob/{id}` — удаляет блоб (получатель подтверждает приём, чтобы
/// не держать вложение на сервере дольше нужного — §7.3/§10.9). Идемпотентно.
async fn delete_blob(
    Path(id): Path<String>,
    State(st): State<Shared>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_id(&id)?;
    let n = st.store.delete_blob(&id).map_err(ApiError::internal)?;
    Ok(Json(json!({ "deleted": n })))
}

// --- Каталог обнаружения: удалённое добавление контакта ---------------------

#[derive(Deserialize)]
struct TtlQuery {
    ttl: Option<i64>,
}

/// `PUT /v1/directory/{index}` — публикует ЗАПЕЧАТАННУЮ запись каталога.
///
/// Zero-trust (§10.9): тело — непрозрачный шифртекст (XChaCha20-Poly1305 на
/// ключе, выведённом из тега обнаружения владельца; тега у сервера нет). `index`
/// — 256-бит capability, выведенный из того же тега, поэтому перезаписать запись
/// может только владелец тега, а перечислить каталог нельзя. Сервер не знает ни
/// чья это запись, ни что внутри, ни кто её потом запрашивал.
///
/// `?ttl=<сек>` — желаемый срок публикации, клемпится `AEGIS_DIRECTORY_MAX_TTL_SECS`.
async fn put_directory(
    Path(index): Path<String>,
    Query(q): Query<TtlQuery>,
    State(st): State<Shared>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !st.cfg.directory_enabled {
        return Err(ApiError::NotFound);
    }
    validate_id(&index)?;
    if body.is_empty() {
        return Err(ApiError::bad_request("пустая запись каталога"));
    }
    if body.len() > st.cfg.directory_max_bytes {
        return Err(ApiError::bad_request("запись каталога слишком велика"));
    }
    let now = now_secs();
    let ttl = q.ttl.unwrap_or(st.cfg.directory_max_ttl_secs).clamp(60, st.cfg.directory_max_ttl_secs);
    st.store
        .put_directory(&index, &body, now, now + ttl, &st.cfg.store_limits())
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true, "expiresIn": ttl })))
}

/// `GET /v1/directory/{index}` — отдаёт запечатанную запись или 404.
///
/// Ответ неотличим для сервера от любого другого шифртекста; расшифровать и
/// ПРОВЕРИТЬ подпись/привязку accountId обязан клиент (fail-closed).
async fn get_directory(
    Path(index): Path<String>,
    State(st): State<Shared>,
) -> Result<Response, ApiError> {
    if !st.cfg.directory_enabled {
        return Err(ApiError::NotFound);
    }
    validate_id(&index)?;
    match st.store.get_directory(&index, now_secs()).map_err(ApiError::internal)? {
        Some(data) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response()),
        None => Err(ApiError::NotFound),
    }
}

/// `DELETE /v1/directory/{index}` — снимает запись с публикации. Отдельной
/// аутентификации не нужно: знание `index` (256 бит из тега) и есть capability,
/// как и для mailbox. Идемпотентно.
async fn delete_directory(
    Path(index): Path<String>,
    State(st): State<Shared>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !st.cfg.directory_enabled {
        return Err(ApiError::NotFound);
    }
    validate_id(&index)?;
    let n = st.store.delete_directory(&index).map_err(ApiError::internal)?;
    Ok(Json(json!({ "deleted": n })))
}

#[derive(Deserialize)]
struct AliasBody {
    claim: String,
    sig: String,
}

/// `PUT /v1/alias/{index}` — занимает или продлевает ПУБЛИЧНЫЙ алиас (`@ник`).
///
/// Единственный маршрут, где сервер проверяет подпись — иначе алиас угонялся бы
/// перезаписью, и клиент, впервые ищущий ник, не смог бы отличить подмену
/// (обоснование и границы — [`crate::directory`]). Правило: свободный алиас
/// занимает кто угодно, занятый обновляет только владелец того же ключа и только
/// более свежей заявкой.
///
/// Публичное пространство имён перечислимо по построению, поэтому маршрут
/// закрыт proof-of-work (`AEGIS_POW_BITS`) и выключен по умолчанию
/// (`AEGIS_ALIAS_ENABLED=0`).
async fn put_alias(
    Path(index): Path<String>,
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<AliasBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !st.cfg.alias_enabled {
        return Err(ApiError::NotFound);
    }
    validate_id(&index)?;
    require_pow(&st, &headers, &format!("/v1/alias/{index}"))?;

    let now_s = now_secs();
    let now_ms = now_s * 1000;
    let existing = st.store.alias_guard(&index, now_s).map_err(ApiError::internal)?;
    let verified =
        directory::verify_alias_claim(&body.claim, &body.sig, &index, existing.as_ref(), now_ms)
            .map_err(|e| match e {
                ClaimError::Conflict(_) => ApiError::Conflict(e.message().to_string()),
                other => ApiError::BadRequest(other.message().to_string()),
            })?;

    st.store
        .put_alias(
            &index,
            body.claim.trim(),
            body.sig.trim(),
            &verified.ed25519_hex,
            verified.issued_at_ms,
            now_s,
            verified.expires_at_ms / 1000,
            &st.cfg.store_limits(),
        )
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true, "expiresAtMs": verified.expires_at_ms })))
}

/// `GET /v1/alias/{index}` — отдаёт подписанную заявку дословно (или 404).
/// Клиент ОБЯЗАН перепроверить подпись и привязку `accountId` сам: заявка
/// самодостаточна, доверять ответу сервера не нужно.
async fn get_alias(
    Path(index): Path<String>,
    State(st): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !st.cfg.alias_enabled {
        return Err(ApiError::NotFound);
    }
    validate_id(&index)?;
    require_pow(&st, &headers, &format!("/v1/alias/{index}"))?;
    match st.store.get_alias(&index, now_secs()).map_err(ApiError::internal)? {
        Some(claim) => Ok(Json(json!({ "claim": claim.claim_b64, "sig": claim.sig_b64 }))),
        None => Err(ApiError::NotFound),
    }
}

/// `GET /v1/params` — параметры каталога для клиента: что включено на этом релее
/// и какая сложность proof-of-work требуется. Позволяет клиенту не угадывать
/// (иначе он либо считал бы PoW зря, либо получал 400 и молча деградировал).
/// Никаких секретов и метаданных пользователей здесь нет.
async fn params(State(st): State<Shared>) -> Json<serde_json::Value> {
    Json(json!({
        "v": 1,
        "directory": st.cfg.directory_enabled,
        "alias": st.cfg.alias_enabled,
        "powBits": pow::effective_bits(st.cfg.pow_bits),
        "powEpochSecs": pow::EPOCH_SECS,
        "directoryMaxBytes": st.cfg.directory_max_bytes,
        "directoryMaxTtlSecs": st.cfg.directory_max_ttl_secs,
        "aliasMaxTtlMs": crate::directory::MAX_TTL_MS,
    }))
}

/// Проверяет заголовок `X-Aegis-Pow` для публичных маршрутов алиасов.
fn require_pow(st: &Shared, headers: &HeaderMap, path: &str) -> Result<(), ApiError> {
    let header = headers.get(POW_HEADER).and_then(|v| v.to_str().ok());
    pow::verify(header, path, now_secs(), st.cfg.pow_bits)
        .map_err(|e| ApiError::PowRequired(e.message().to_string()))
}

/// `GET /v1/turn` — выдаёт эфемерные TURN-креды для медиа звонков (§7.5/§10.10).
/// Анонимно (как и mailbox): знание адреса релея — достаточная capability,
/// личность серверу не нужна. 404, если нет секрета или ни одного способа
/// подключиться к coturn (ни onion, ни клирнет-URI).
///
/// Zero-trust (§10.9): `static-auth-secret` клиенту НЕ раскрывается — только
/// производные `username`/`credential`; медиа сквозное (DTLS-SRTP), coturn видит
/// лишь шифртекст.
async fn turn_credentials(State(st): State<Shared>) -> Result<Json<serde_json::Value>, ApiError> {
    let cfg = &st.cfg;
    if !cfg.turn_enabled() {
        return Err(ApiError::NotFound);
    }
    let creds = turn::make_credentials(&cfg.turn_secret, now_secs(), cfg.turn_ttl, &turn_nonce());
    // `onion`/`port` — TCP-TURN за onion для режима Tor (пусто, если onion-TURN
    // не настроен; старые клиенты тогда считают TURN выключенным, как и раньше).
    // `stun` — устаревшее поле для клиентов с «медиа напрямую» при Tor.
    // `uris` — аддитивное поле: клирнет STUN/TURN/TURNS своего coturn для режима
    // без Tor. Старые клиенты его не читают, клиент в режиме Tor не использует.
    Ok(Json(json!({
        "onion": cfg.turn_onion,
        "port": cfg.turn_port,
        "username": creds.username,
        "credential": creds.credential,
        "realm": cfg.turn_realm,
        "ttl": cfg.turn_ttl,
        "expiry": creds.expiry,
        "stun": cfg.stun_public,
        "uris": cfg.turn_public_uris,
    })))
}

/// `GET /v1/config` — отдаёт подписанный офлайн конфиг-документ с актуальным
/// адресом(ами) onion-релея, чтобы клиент не вводил его вручную и подхватывал
/// ротацию/резерв (§12.2). Тело: `{ "doc": "<b64 payload>", "sig": "<b64 sig>" }`.
///
/// Zero-trust (§10.9): сервер приватного ключа подписи НЕ имеет — он лишь
/// отдаёт заранее подписанные офлайн строки (`AEGIS_CONFIG_DOC`/`AEGIS_CONFIG_SIG`).
/// Клиент проверяет подпись зашитым в APK публичным ключом Ed25519, поэтому даже
/// полностью скомпрометированный сервер не может подменить адрес. Если документ
/// не задан → 404 (клиент останется на зашитом в сборку адресе по умолчанию).
async fn server_config(State(st): State<Shared>) -> Result<Json<serde_json::Value>, ApiError> {
    let cfg = &st.cfg;
    if !cfg.config_enabled() {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({
        "doc": cfg.config_doc,
        "sig": cfg.config_sig,
    })))
}

/// Непрозрачная строка уникальности для username TURN (не секрет; лишь чтобы
/// креды разных запросов не совпадали). Наносекунды монотонны достаточно для этого.
fn turn_nonce() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("{:x}", d.as_nanos()))
        .unwrap_or_default()
}

// --- Валидация и утилиты ----------------------------------------------------

/// Идентификатор mailbox/prekey — URL-safe base64 без паддинга (256 бит → 43
/// символа); допускаем 8..=64 символа из безопасного алфавита.
fn validate_id(id: &str) -> Result<(), ApiError> {
    let ok = (8..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request("некорректный идентификатор mailbox"))
    }
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// --- Ошибки -----------------------------------------------------------------

pub enum ApiError {
    BadRequest(String),
    NotFound,
    /// Алиас занят другим ключом либо заявка не новее действующей.
    Conflict(String),
    /// Не пройден proof-of-work публичного маршрута (клиент решает и повторяет).
    PowRequired(String),
    Internal,
}

impl ApiError {
    fn bad_request(msg: &str) -> Self {
        ApiError::BadRequest(msg.to_string())
    }
    fn internal<E: std::fmt::Display>(e: E) -> Self {
        tracing::error!(error = %e, "внутренняя ошибка");
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "не найдено".to_string()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            // 429: клиенту нужно посчитать PoW и повторить — это не «плохой
            // запрос», а требование выполнить работу.
            ApiError::PowRequired(m) => (StatusCode::TOO_MANY_REQUESTS, m),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "ошибка сервера".to_string()),
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        let store = Store::open_in_memory().unwrap();
        router(Arc::new(AppState::new(store, Config::from_env())))
    }

    fn app_with_cfg(cfg: Config) -> Router {
        let store = Store::open_in_memory().unwrap();
        router(Arc::new(AppState::new(store, cfg)))
    }

    const ID: &str = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH0123456789a"; // 43 симв.

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = app()
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "ok");
    }

    #[tokio::test]
    async fn drop_poll_ack_roundtrip() {
        let app = app();

        // Дроп конверта.
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/mailbox/{ID}"))
                    .body(Body::from("ciphertext-envelope"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["seq"], 1);

        // Немедленный poll (wait=0) возвращает конверт (base64).
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/v1/mailbox/{ID}?after=0")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["next"], 1);
        let data = base64::engine::general_purpose::STANDARD
            .decode(v["items"][0]["dataB64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data, b"ciphertext-envelope");

        // Ack удаляет; повторный poll пуст.
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/mailbox/{ID}/ack"))
                    .header("content-type", "application/json")
                    .body(Body::from("{\"upto\":1}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["acked"], 1);

        let resp = app
            .oneshot(Request::get(format!("/v1/mailbox/{ID}?after=0")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rejects_invalid_mailbox_id() {
        let resp = app()
            .oneshot(Request::get("/v1/mailbox/short?after=0").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prekey_publish_and_fetch() {
        let app = app();
        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/prekeys/{ID}"))
                    .body(Body::from("{\"identity\":\"x\"}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(Request::get(format!("/v1/prekeys/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["identity"], "x");
    }

    #[tokio::test]
    async fn blob_put_get_delete_roundtrip() {
        let app = app();

        // Загрузка блоба (octet-stream).
        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/blob/{ID}"))
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(vec![1u8, 2, 3, 4, 5]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["ok"], true);

        // Скачивание возвращает те же байты.
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/v1/blob/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), &[1u8, 2, 3, 4, 5]);

        // Удаление; повторное скачивание — 404.
        let resp = app
            .clone()
            .oneshot(Request::delete(format!("/v1/blob/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["deleted"], 1);

        let resp = app
            .oneshot(Request::get(format!("/v1/blob/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn blob_missing_returns_404() {
        let resp = app()
            .oneshot(Request::get(format!("/v1/blob/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn turn_disabled_returns_404() {
        // Config::from_env без AEGIS_TURN_* → TURN выключен.
        let resp = app()
            .oneshot(Request::get("/v1/turn").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn turn_enabled_returns_credentials() {
        let cfg = Config {
            turn_secret: "shared-secret".to_string(),
            turn_onion: "exampleonionaddressv3id.onion".to_string(),
            turn_port: 3478,
            turn_realm: "aegis".to_string(),
            ..Config::from_env()
        };
        let resp = app_with_cfg(cfg)
            .oneshot(Request::get("/v1/turn").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["onion"], "exampleonionaddressv3id.onion");
        assert_eq!(v["port"], 3478);
        assert!(v["username"].as_str().unwrap().contains(':'));
        assert!(!v["credential"].as_str().unwrap().is_empty());
        assert_eq!(v["realm"], "aegis");
        // STUN не задан → поле присутствует, но пустое: клиент по нему понимает,
        // что прямой путь через STUN сервером не предлагается.
        assert_eq!(v["stun"], "");
        // Клирнет-URI не заданы → пустой массив: режим без Tor остаётся без TURN.
        assert_eq!(v["uris"], json!([]));
    }

    /// Клирнет STUN/TURN для клиентов в режиме «Tor ВЫКЛ» отдаются рядом со
    /// старыми полями — те не меняются, чтобы старые клиенты работали как раньше.
    #[tokio::test]
    async fn turn_reports_clearnet_uris_next_to_legacy_fields() {
        let uris = vec![
            "stun:relay.example.com:3478".to_string(),
            "turn:relay.example.com:3478?transport=udp".to_string(),
            "turns:relay.example.com:5349?transport=tcp".to_string(),
        ];
        let cfg = Config {
            turn_secret: "shared-secret".to_string(),
            turn_onion: "exampleonionaddressv3id.onion".to_string(),
            turn_public_uris: uris.clone(),
            ..Config::from_env()
        };
        let resp = app_with_cfg(cfg)
            .oneshot(Request::get("/v1/turn").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["onion"], "exampleonionaddressv3id.onion");
        assert_eq!(v["port"], 3478);
        assert!(!v["credential"].as_str().unwrap().is_empty());
        assert_eq!(v["uris"], json!(uris));
    }

    /// Оператор без onion-TURN, но с клирнет-coturn: TURN включён, `onion`
    /// пустой (старый клиент воспримет это как «TURN нет», как и раньше).
    #[tokio::test]
    async fn turn_works_without_onion_when_clearnet_uris_are_set() {
        let cfg = Config {
            turn_secret: "shared-secret".to_string(),
            turn_onion: String::new(),
            turn_public_uris: vec!["turn:relay.example.com:3478?transport=tcp".to_string()],
            ..Config::from_env()
        };
        let resp = app_with_cfg(cfg)
            .oneshot(Request::get("/v1/turn").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["onion"], "");
        assert_eq!(v["uris"][0], "turn:relay.example.com:3478?transport=tcp");
    }

    /// Секрет есть, но подключиться не к чему — 404, а не креды «в никуда».
    #[tokio::test]
    async fn turn_without_onion_or_uris_returns_404() {
        let cfg = Config {
            turn_secret: "shared-secret".to_string(),
            turn_onion: String::new(),
            turn_public_uris: Vec::new(),
            ..Config::from_env()
        };
        let resp = app_with_cfg(cfg)
            .oneshot(Request::get("/v1/turn").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Релей не пишет в журнал ни адресов, ни заголовков: даже прокинутый фронтом
    /// `X-Forwarded-For` не влияет на ответ и нигде не используется. Регрессия на
    /// случай, если кто-то подключит слой трассировки запросов.
    #[tokio::test]
    async fn forwarded_headers_are_ignored() {
        let resp = app()
            .oneshot(
                Request::get("/v1/health")
                    .header("x-forwarded-for", "203.0.113.7")
                    .header("forwarded", "for=203.0.113.7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert!(!v.to_string().contains("203.0.113.7"));
    }

    /// Публичный STUN отдаётся клиенту, когда администратор его настроил.
    ///
    /// Отдельный тест, потому что это единственное поле ответа, из-за которого
    /// клиент может раскрыть свой IP серверу: молчаливая регрессия здесь означала
    /// бы либо неработающий прямой путь, либо (при обратной ошибке) раздачу STUN
    /// там, где администратор его не включал.
    #[tokio::test]
    async fn turn_reports_public_stun_when_configured() {
        let cfg = Config {
            turn_secret: "shared-secret".to_string(),
            turn_onion: "exampleonionaddressv3id.onion".to_string(),
            stun_public: "stun.example.com:3478".to_string(),
            ..Config::from_env()
        };
        let resp = app_with_cfg(cfg)
            .oneshot(Request::get("/v1/turn").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["stun"], "stun.example.com:3478");
    }

    #[tokio::test]
    async fn config_disabled_returns_404() {
        // Config::from_env без AEGIS_CONFIG_* → авто-раздача выключена.
        let resp = app()
            .oneshot(Request::get("/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn config_enabled_returns_signed_doc() {
        let cfg = Config {
            config_doc: "ZG9jLXBheWxvYWQ".to_string(), // произвольный b64
            config_sig: "c2lnbmF0dXJl".to_string(),
            ..Config::from_env()
        };
        let resp = app_with_cfg(cfg)
            .oneshot(Request::get("/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["doc"], "ZG9jLXBheWxvYWQ");
        assert_eq!(v["sig"], "c2lnbmF0dXJl");
    }

    #[test]
    fn id_validation() {
        assert!(validate_id(ID).is_ok());
        assert!(validate_id("short").is_err());
        assert!(validate_id("has spaces and+slash/").is_err());
        assert!(validate_id(&"A".repeat(65)).is_err());
    }

    // --- Каталог обнаружения ------------------------------------------------

    fn directory_cfg() -> Config {
        Config { directory_enabled: true, ..Config::from_env() }
    }

    #[tokio::test]
    async fn directory_put_get_delete_roundtrip() {
        let app = app_with_cfg(directory_cfg());

        // Публикация запечатанной записи (для сервера — непрозрачные байты).
        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/directory/{ID}"))
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(vec![9u8, 8, 7, 6]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["ok"], true);

        // Чтение отдаёт те же байты.
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/v1/directory/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), &[9u8, 8, 7, 6]);

        // Снятие с публикации.
        let resp = app
            .clone()
            .oneshot(Request::delete(format!("/v1/directory/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["deleted"], 1);

        let resp = app
            .oneshot(Request::get(format!("/v1/directory/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn directory_rejects_empty_oversized_and_bad_index() {
        let cfg = Config { directory_max_bytes: 1024, ..directory_cfg() };
        let app = app_with_cfg(cfg);

        let resp = app
            .clone()
            .oneshot(Request::put(format!("/v1/directory/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/directory/{ID}"))
                    .body(Body::from(vec![0u8; 2048]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .oneshot(Request::get("/v1/directory/short").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Оператор может выключить каталог — маршруты становятся 404, и клиенты
    /// откатываются на обмен по QR/NFC.
    #[tokio::test]
    async fn directory_disabled_returns_404() {
        let app = app_with_cfg(Config { directory_enabled: false, ..Config::from_env() });
        let resp = app
            .oneshot(Request::get(format!("/v1/directory/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // --- Публичные алиасы ---------------------------------------------------

    /// Публичный каталог алиасов выключен по умолчанию (перечислим по построению).
    #[tokio::test]
    async fn alias_disabled_by_default() {
        let resp = app()
            .oneshot(Request::get(format!("/v1/alias/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    fn alias_cfg(pow_bits: u32) -> Config {
        Config { alias_enabled: true, pow_bits, ..Config::from_env() }
    }

    /// Собирает подписанную заявку на алиас так же, как это делает клиент.
    fn signed_claim(
        signing: &ed25519_dalek::SigningKey,
        alias_index: &str,
        issued_ms: i64,
        expires_ms: i64,
    ) -> serde_json::Value {
        use ed25519_dalek::Signer;
        let b64 = base64::engine::general_purpose::STANDARD;
        let ed_pub = signing.verifying_key().to_bytes();
        let payload = json!({
            "v": 1,
            "aliasIndex": alias_index,
            "accountId": crate::directory::account_id_from(&ed_pub),
            "ed25519": ed_pub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "discoveryIndex": ID,
            "tagB64": b64.encode([3u8; 32]),
            "nickname": "alice",
            "issuedAtMs": issued_ms,
            "expiresAtMs": expires_ms,
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        json!({
            "claim": b64.encode(&bytes),
            "sig": b64.encode(signing.sign(&bytes).to_bytes()),
        })
    }

    fn now_ms() -> i64 {
        now_secs() * 1000
    }

    #[tokio::test]
    async fn alias_claim_and_fetch_roundtrip() {
        let app = app_with_cfg(alias_cfg(0));
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let claim = signed_claim(&key, ID, now_ms(), now_ms() + 86_400_000);

        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/alias/{ID}"))
                    .header("content-type", "application/json")
                    .body(Body::from(claim.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(Request::get(format!("/v1/alias/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["claim"], claim["claim"]);
        assert_eq!(v["sig"], claim["sig"]);
    }

    /// Главное свойство серверной проверки: занятый алиас нельзя угнать чужим
    /// ключом простой перезаписью (иначе клиент, впервые ищущий ник, получил бы
    /// ключи злоумышленника и не смог бы отличить подмену).
    #[tokio::test]
    async fn alias_hijack_is_rejected_with_conflict() {
        let app = app_with_cfg(alias_cfg(0));
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);

        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/alias/{ID}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        signed_claim(&owner, ID, now_ms(), now_ms() + 86_400_000).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/alias/{ID}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        signed_claim(&attacker, ID, now_ms() + 1000, now_ms() + 86_400_000)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // Запись осталась за владельцем.
        let resp = app
            .oneshot(Request::get(format!("/v1/alias/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let v = body_json(resp).await;
        let owner_claim = signed_claim(&owner, ID, now_ms(), now_ms() + 86_400_000);
        assert_eq!(v["sig"], owner_claim["sig"]);
    }

    #[tokio::test]
    async fn alias_rejects_bad_signature() {
        let app = app_with_cfg(alias_cfg(0));
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let mut claim = signed_claim(&key, ID, now_ms(), now_ms() + 86_400_000);
        claim["sig"] = json!(base64::engine::general_purpose::STANDARD.encode([0u8; 64]));

        let resp = app
            .oneshot(
                Request::put(format!("/v1/alias/{ID}"))
                    .header("content-type", "application/json")
                    .body(Body::from(claim.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Без решения proof-of-work публичный маршрут отвечает 429 (клиент считает
    /// работу и повторяет), а не пускает словарное перечисление никнеймов.
    #[tokio::test]
    async fn alias_requires_pow_when_enabled() {
        let app = app_with_cfg(alias_cfg(12));
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/v1/alias/{ID}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // С решением — обычный 404 (алиас просто не занят).
        let path = format!("/v1/alias/{ID}");
        let header = pow::solve(&path, pow::epoch_for(now_secs()), 12);
        let resp = app
            .oneshot(Request::get(&path).header(POW_HEADER, header).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn params_reports_capabilities() {
        let app = app_with_cfg(Config { alias_enabled: true, pow_bits: 18, ..directory_cfg() });
        let resp = app
            .oneshot(Request::get("/v1/params").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["directory"], true);
        assert_eq!(v["alias"], true);
        assert_eq!(v["powBits"], 18);
        assert_eq!(v["powEpochSecs"], pow::EPOCH_SECS);
    }

    /// Регрессия на утечку памяти: карта пробуждателей не должна расти после
    /// завершённых long-poll (раньше запись оставалась навсегда — по одной на
    /// каждый когда-либо опрошенный ящик).
    #[tokio::test]
    async fn notifiers_do_not_leak_after_polls() {
        let store = Store::open_in_memory().unwrap();
        let state = Arc::new(AppState::new(store, Config::from_env()));
        let app = router(state.clone());

        for i in 0..20 {
            let mailbox = format!("{}{:02}", &ID[..41], i);
            let resp = app
                .clone()
                .oneshot(
                    Request::get(format!("/v1/mailbox/{mailbox}?after=0&wait=0"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        assert_eq!(
            state.notifier_count(),
            0,
            "пробуждатели завершённых long-poll должны освобождаться"
        );
    }

    /// Регрессия на DoS диска через дропы в неограниченное число новых ящиков.
    #[tokio::test]
    async fn global_cap_limits_disk_usage_across_mailboxes() {
        let cfg = Config { max_total_messages: 20, ..Config::from_env() };
        let store = Store::open_in_memory().unwrap();
        let state = Arc::new(AppState::new(store, cfg));
        let app = router(state.clone());

        for i in 0..100 {
            let mailbox = format!("{}{:03}", &ID[..40], i);
            let resp = app
                .clone()
                .oneshot(
                    Request::post(format!("/v1/mailbox/{mailbox}"))
                        .body(Body::from("spam-envelope"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let queued = state.store.queued().unwrap();
        assert!(queued <= 20, "глобальный потолок не сработал: {queued} конвертов");
    }
}

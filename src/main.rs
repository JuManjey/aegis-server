//! AEGIS relay — zero-trust сервер доставки E2EE-конвертов (§7.6/§12.2).
//!
//! Роль минимальна (§9): доставка зашифрованных пакетов + offline-очередь +
//! хранение публичных prekeys + сигналинг звонков (тот же конвейер mailbox).
//! Сервер НЕ видит plaintext, личности и связь «кто-кому» — только непрозрачный
//! шифртекст в очередях, адресуемых 256-бит идентификаторами из PSK клиента.
//!
//! Наружу сервис публикуется как **Onion Service v3** (tor-демон форвардит
//! HS→127.0.0.1:8080), поэтому приложение по умолчанию слушает только localhost.

mod api;
mod config;
mod directory;
mod pow;
mod store;
mod turn;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::api::AppState;
use crate::config::Config;
use crate::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_relay=info,tower_http=info".into()),
        )
        .init();

    let cfg = Config::from_env();
    tracing::info!(
        db = %cfg.db_path,
        max_body = cfg.max_body,
        max_queue = cfg.max_queue,
        max_total_messages = cfg.max_total_messages,
        max_total_bytes = cfg.max_total_bytes,
        blob_max_bytes = cfg.blob_max_bytes,
        max_blobs = cfg.max_blobs,
        ttl_secs = cfg.ttl_secs,
        directory = cfg.directory_enabled,
        alias = cfg.alias_enabled,
        pow_bits = cfg.pow_bits,
        "конфигурация загружена"
    );
    tracing::info!(
        turn = cfg.turn_enabled(),
        turn_onion = !cfg.turn_onion.is_empty(),
        turn_public_uris = cfg.turn_public_uris.len(),
        "TURN"
    );
    for rejected in &cfg.rejected_turn_uris {
        tracing::warn!(uri = %rejected, "AEGIS_TURN_PUBLIC_URIS: запись не распознана и клиентам не отдаётся");
    }
    if cfg.alias_enabled && cfg.pow_bits == 0 {
        tracing::warn!(
            "публичный каталог алиасов включён БЕЗ proof-of-work (AEGIS_POW_BITS=0): \
             пространство имён перечислимо словарной атакой без каких-либо издержек"
        );
    }

    let store = Store::open(&cfg.db_path)?;
    let state = Arc::new(AppState::new(store, cfg.clone()));

    spawn_sweeper(state.clone());

    let app = api::router(state.clone());
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!(bind = %cfg.bind, "aegis-relay слушает (наружу — только через Tor HS v3)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("aegis-relay остановлен");
    Ok(())
}

/// Фоновая уборка сообщений старше TTL (жёсткий потолок хранения §7.3), а также
/// просроченных записей каталога и заявок на алиасы (их срок задаёт владелец).
fn spawn_sweeper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let ttl = state.cfg.ttl_secs;
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let now = now_secs();
            match state.store.sweep(now - ttl, now) {
                Ok(n) if n > 0 => tracing::info!(removed = n, "sweeper: удалены просроченные конверты"),
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "sweeper: ошибка уборки"),
            }
        }
    });
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Ожидает SIGINT (Ctrl-C) или SIGTERM (docker stop) для корректной остановки.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("не удалось поставить обработчик Ctrl-C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("не удалось поставить обработчик SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("получен сигнал остановки, завершаемся");
}

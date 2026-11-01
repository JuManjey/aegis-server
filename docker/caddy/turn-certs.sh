#!/bin/sh
# AEGIS — доставка сертификата Let's Encrypt от Caddy в coturn (TURNS 5349).
#
# Caddy сам получает и продлевает сертификат домена, но кладёт ключ с правами
# root:root 0600, а coturn работает от nobody. Этот сервис раз в час (а пока
# сертификата у coturn нет — каждые 15 с) сверяет сертификат Caddy с копией для
# coturn и, если он поменялся:
#   * копирует cert/key в общий том с владельцем nobody (65534) и правами 0600;
#   * если сертификата раньше не было — завершает coturn (restart: unless-stopped
#     поднимет его уже с TLS-листенером; без сертификата при старте coturn
#     TLS-порт не открывает);
#   * иначе шлёт coturn SIGUSR2 — он перечитывает сертификат без разрыва звонков.
#
# Сервис запущен в пространстве PID coturn (pid: service:coturn). PID 1 там —
# docker-init (init: true у coturn), он пересылает сигналы turnserver: сам
# turnserver как PID 1 SIGTERM бы проигнорировал. Сети у сервиса нет
# (network_mode: none).
set -eu

DOMAIN="${AEGIS_TURN_DOMAIN:?укажите AEGIS_TURN_DOMAIN}"
SRC_ROOT="${AEGIS_CADDY_CERTS_DIR:-/data/caddy/certificates}"
DST="${AEGIS_TURN_CERTS_DIR:-/turn-certs}"
COTURN_PID="${AEGIS_COTURN_PID:-1}"
INTERVAL="${AEGIS_TURN_CERT_CHECK_SECS:-3600}"
# Caddy получает первый сертификат через секунды после старта, обычно позже
# первой проверки здесь: час ожидания оставил бы TURNS выключенным.
FIRST_INTERVAL="${AEGIS_TURN_CERT_FIRST_CHECK_SECS:-15}"

log() { echo "turn-certs: $*"; }

find_src() {
    # Каталог издателя зависит от CA (Let's Encrypt, ZeroSSL) — ищем по домену.
    for dir in "$SRC_ROOT"/*/"$DOMAIN"; do
        if [ -s "$dir/$DOMAIN.crt" ] && [ -s "$dir/$DOMAIN.key" ]; then
            echo "$dir"
            return 0
        fi
    done
    return 1
}

waiting_logged=0
while true; do
    if src="$(find_src)"; then
        # Сравниваем со своей копией (root): файлы coturn принадлежат nobody с
        # правами 0600, и без лишних capabilities их не прочитать.
        if ! cmp -s "$src/$DOMAIN.crt" "$DST/.installed.crt" 2>/dev/null; then
            first=0
            [ -s "$DST/cert.pem" ] || first=1
            rm -f "$DST/cert.pem.new" "$DST/key.pem.new"
            cp "$src/$DOMAIN.crt" "$DST/cert.pem.new"
            cp "$src/$DOMAIN.key" "$DST/key.pem.new"
            # Сначала права, потом владелец: у сервиса нет CAP_FOWNER, а менять
            # права уже чужого (nobody) файла без неё нельзя.
            chmod 0600 "$DST/cert.pem.new" "$DST/key.pem.new"
            chown 65534:65534 "$DST/cert.pem.new" "$DST/key.pem.new"
            mv "$DST/key.pem.new" "$DST/key.pem"
            mv "$DST/cert.pem.new" "$DST/cert.pem"
            cp "$src/$DOMAIN.crt" "$DST/.installed.crt"
            if [ "$first" = 1 ]; then
                log "первый сертификат для $DOMAIN — перезапуск coturn для TLS-листенера"
                kill -TERM "$COTURN_PID" || true
            else
                log "сертификат $DOMAIN обновлён — coturn перечитывает его (SIGUSR2)"
                kill -USR2 "$COTURN_PID" || true
            fi
        fi
    elif [ "$waiting_logged" = 0 ]; then
        log "сертификата для $DOMAIN у Caddy пока нет (DNS, порты 80/443?) — жду"
        waiting_logged=1
    fi
    if [ -s "$DST/cert.pem" ]; then
        sleep "$INTERVAL"
    else
        sleep "$FIRST_INTERVAL"
    fi
done

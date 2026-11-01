# AEGIS — сервер (релей) защищённого мессенджера

> **ВНИМАНИЕ: проект не завершён.**
>
> AEGIS — рабочий, но **не законченный** прототип. Сервер выполняет свою задачу
> (доставка зашифрованных сообщений, вложений и сигналинга звонков, TURN для
> медиа), однако в нём есть известные недоработки — прежде всего в защите от
> злоупотреблений и в защите метаданных. Они честно перечислены в разделе
> [«Известные ограничения»](#известные-ограничения).
>
> - Независимый аудит безопасности **не проводился**.
> - Протокол и форматы данных могут меняться без обратной совместимости.
> - Не полагайтесь на AEGIS там, где от защиты переписки зависят жизнь, свобода
>   или безопасность людей.
>
> Готового общего сервера нет: каждый, кто хочет пользоваться AEGIS, разворачивает
> свой сервер по этой инструкции и собирает приложение (репозиторий
> **`aegis-client`**) с адресом этого сервера.

Это **серверная часть** мессенджера AEGIS — релей с «почтовыми ящиками», через
который Android-приложения обмениваются **только зашифрованными** конвертами.
Сервер не видит текста сообщений, ключей и имён пользователей. Снаружи он
доступен как **Tor Onion Service v3**: открытые порты в интернет для этого не
нужны.

Клиент (Android-приложение) — в репозитории **`aegis-client`**.
Лицензия — **GPL-3.0-or-later** (см. [`LICENSE`](LICENSE)).

## Содержание

- [Статус проекта](#статус-проекта)
- [Что делает сервер](#что-делает-сервер)
- [Два режима доступа](#два-режима-доступа)
- [Что понадобится](#что-понадобится)
- [Шаг 1. Подготовка сервера](#шаг-1-подготовка-сервера)
- [Шаг 2. Установка Docker](#шаг-2-установка-docker)
- [Шаг 3. Код и настройка .env](#шаг-3-код-и-настройка-env)
- [Шаг 4. Первый запуск](#шаг-4-первый-запуск)
- [Шаг 5. TURN для звонков](#шаг-5-turn-для-звонков)
- [Шаг 6. Проверка](#шаг-6-проверка)
- [Шаг 7. Подключение приложения](#шаг-7-подключение-приложения)
- [Клирнет-профиль](#клирнет-профиль)
- [Подписанный конфиг](#подписанный-конфиг)
- [Публичный STUN](#публичный-stun)
- [Настройки .env](#настройки-env)
- [Данные и резервные копии](#данные-и-резервные-копии)
- [Обновление](#обновление)
- [Логи и мониторинг](#логи-и-мониторинг)
- [API](#api)
- [Разработка и тесты](#разработка-и-тесты)
- [Воспроизводимые сборки](#воспроизводимые-сборки)
- [Структура репозитория](#структура-репозитория)
- [Известные ограничения](#известные-ограничения)
- [Решение проблем](#решение-проблем)
- [Лицензия](#лицензия)

---

## Статус проекта

Версия релея — **0.1.0**; совместим с клиентом AEGIS **0.4.2**.

### Что реализовано и работает

- Анонимные «почтовые ящики»: приём конвертов, long-poll выдача, подтверждение
  получения, офлайн-очередь в SQLite. Конверты старше **7 суток** удаляются
  автоматически.
- Хранилище зашифрованных вложений и голосовых сообщений (blob).
- Публичные prekey-бандлы для протокола Signal.
- Приватный каталог для удалённого добавления контактов (сервер хранит только
  запечатанные записи, перечислить их нельзя).
- Эфемерные креды TURN для звонков (`GET /v1/turn`) и coturn, доступный через
  отдельный onion-адрес.
- Публикация как Tor Onion Service v3 — без единого открытого порта.
- Необязательный клирнет-профиль для клиентов с выключенным Tor: HTTPS (Caddy +
  Let's Encrypt с автопродлением) и STUN/TURN/TURNS.
- Подписанный офлайн-ключом конфиг с адресом сервера (`GET /v1/config`).
- Лимиты хранения, CI на GitHub Actions, воспроизводимая сборка.

### Что не доделано (кратко)

- Нет ограничения частоты запросов; при переполнении вытесняются самые старые
  данные по всей базе — злоумышленник может «вымыть» чужие недоставленные
  сообщения.
- Оператор сервера может связать ящики одного клиента и восстановить
  псевдонимный граф «кто с кем общается».
- Публикация `@ника` несовместима с клиентом 0.4.2.

Подробно — в разделе [«Известные ограничения»](#известные-ограничения).

---

## Что делает сервер

Стек поднимается через Docker Compose:

| Сервис | Контейнер | Роль |
|---|---|---|
| `relay` | `aegis-relay` | HTTP-релей на Rust (axum + tokio): ящики, вложения, prekeys, каталог, креды TURN, конфиг. Данные — SQLite в томе `relay-data` |
| `coturn` | `aegis-coturn` | TURN-сервер для медиа звонков. Пересылает только шифртекст (DTLS-SRTP) и только между аллокациями на самом себе — не открытый прокси |
| `tor` | `aegis-tor` | Публикует два onion-адреса: релей (`443 → relay:8080`) и TURN (`3478 → coturn:3478`). Ключи onion-адресов — в томе `tor-data` |
| `caddy` | `aegis-caddy` | *Только в клирнет-профиле.* HTTPS-фронт релея с сертификатом Let's Encrypt |
| `turn-certs` | `aegis-turn-certs` | *Только в клирнет-профиле.* Передаёт сертификат Caddy в coturn для TURNS |

```
  Приложения                         Ваш сервер
┌───────────┐  Tor   ┌──────────────────────────────────────────────────┐
│ AEGIS #1  │ ─────► │ tor ─┬─► relay:8080 ──► SQLite (том relay-data)   │
├───────────┤        │      │                                           │
│ AEGIS #2  │ ─────► │      └─► coturn:3478 (TURN для звонков)          │
└───────────┘        │                                                  │
                     │ (клирнет-профиль) caddy:443 ──► relay:8080       │
                     │                   coturn:3478/5349 наружу        │
                     └──────────────────────────────────────────────────┘
```

Как это работает с точки зрения сервера:

1. Приложение шифрует сообщение двумя слоями (Signal + каскад на общем секрете
   собеседников) и кладёт непрозрачный конверт в «ящик» —
   `POST /v1/mailbox/{id}`. Идентификатор ящика (256 бит) выводится из секрета
   собеседников; сервер не знает, кому он принадлежит.
2. Получатель забирает конверты long-poll запросом `GET /v1/mailbox/{id}` и
   подтверждает получение.
3. Для звонка приложение берёт у релея временные креды TURN; медиапоток идёт
   через coturn в зашифрованном виде.

Сервер **zero-trust**: в базе только шифртекст, непрозрачные идентификаторы и
время. Единственный настоящий секрет сервера — `AEGIS_TURN_SECRET` (общий
секрет релея и coturn).

---

## Два режима доступа

| Режим | Как подключаются приложения | Что нужно на сервере |
|---|---|---|
| **Onion** (по умолчанию, рекомендуется) | Через встроенный в приложение Tor к onion-адресу. IP пользователей сервер не видит | Ничего, кроме исходящего интернета. Домен, сертификат и открытые порты **не нужны** |
| **Onion + клирнет** (необязательно) | Пользователи, выключившие Tor в приложении, ходят по HTTPS к тому же релею и той же базе | Домен, открытые порты 80/443 TCP, 3478 UDP/TCP, 5349 TCP. См. [«Клирнет-профиль»](#клирнет-профиль) |

Сначала разверните режим Onion (шаги 1–7). Клирнет-профиль добавляется поверх
него в любой момент.

---

## Что понадобится

| Что | Требование |
|---|---|
| Сервер | VPS или свой компьютер с постоянным интернетом |
| ОС | **Debian 12** или **Ubuntu 22.04 / 24.04 LTS**, x86_64 (на arm64 образы тоже есть, но эта конфигурация не проверялась) |
| Ресурсы | 1 vCPU, **2 ГБ ОЗУ** (или 1 ГБ + swap — см. шаг 1.5), 20 ГБ диска |
| Доступ | root или пользователь с `sudo`, вход по SSH |
| Сеть | исходящий интернет (Tor, загрузка образов и зависимостей). Входящие порты для режима Onion не нужны |
| Домен | только для клирнет-профиля |
| Время | 20–40 минут, из них 5–15 минут — сборка релея из исходников |

Релей собирается из исходников прямо при запуске (`docker compose up --build`):
компиляция Rust с LTO требует памяти, на 1 ГБ без swap она может упасть.

---

## Шаг 1. Подготовка сервера

Команды выполняются на сервере.

### 1.1. Обновление системы

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get install -y git curl openssl ca-certificates ufw fail2ban unattended-upgrades
```

### 1.2. Отдельный пользователь

```bash
sudo adduser --disabled-password --gecos "" deploy
sudo usermod -aG sudo deploy
sudo passwd deploy       # пароль для sudo
```

### 1.3. SSH только по ключу

Сначала добавьте свой публичный ключ пользователю `deploy` (с вашего компьютера:
`ssh-copy-id deploy@<IP-сервера>` или вручную в
`/home/deploy/.ssh/authorized_keys`). **Проверьте, что входите по ключу**, и
только после этого отключите пароль и вход под root:

```bash
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### 1.4. Файрвол и защита от перебора

В режиме Onion входящие соединения для мессенджера не нужны: Tor работает через
**исходящие** соединения. Разрешаем только SSH:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw --force enable
sudo systemctl enable --now fail2ban
sudo dpkg-reconfigure -plow unattended-upgrades    # автоматические обновления безопасности
```

### 1.5. Swap (если ОЗУ меньше 2 ГБ)

```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 1.6. Точное время

Tor не работает при заметно сбитых часах. Проверьте синхронизацию:

```bash
timedatectl status | grep -i 'synchronized'   # должно быть: yes
# если нет: sudo timedatectl set-ntp true
```

---

## Шаг 2. Установка Docker

```bash
curl -fsSL https://get.docker.com | sudo sh     # Docker Engine + плагин Compose
sudo usermod -aG docker deploy
```

Перелогиньтесь (выйдите и снова войдите по SSH), чтобы группа `docker`
применилась, затем проверьте:

```bash
docker --version
docker compose version
```

---

## Шаг 3. Код и настройка .env

```bash
sudo mkdir -p /opt/aegis && sudo chown deploy:deploy /opt/aegis
cd /opt/aegis
git clone <URL этого репозитория> aegis-server
cd aegis-server

cp .env.example .env
chmod 600 .env
```

Все значения в `.env.example` уже безопасны, менять их необязательно.
**Обязательно** только одно — общий секрет TURN: без него Docker Compose не
запустит стек (`required variable AEGIS_TURN_SECRET is missing a value`).

```bash
sed -i "s/^AEGIS_TURN_SECRET=.*/AEGIS_TURN_SECRET=$(openssl rand -hex 32)/" .env
grep -c '^AEGIS_TURN_SECRET=.\{64\}$' .env     # должно вывести 1
```

`.env` в git не попадает (он в `.gitignore`). Не публикуйте его: секрет TURN
позволяет выпускать креды для вашего coturn.

---

## Шаг 4. Первый запуск

```bash
docker compose up -d --build
```

Первая сборка образа релея занимает 5–15 минут. Затем стартуют `relay` и
`coturn`, после них — `tor` (он ждёт, пока оба будут готовы).

```bash
docker compose ps
```

Через 1–2 минуты все три сервиса должны быть в состоянии `Up … (healthy)`.
Следить за запуском:

```bash
docker compose logs -f tor       # ждём "Bootstrapped 100% (done): Done"
docker compose logs -f relay     # ждём "конфигурация загружена"
```

Узнайте **onion-адрес релея** — именно его вписывают в приложение:

```bash
docker compose exec -T tor cat /var/lib/tor/aegis/hostname
# пример вида: abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion
```

Адрес сохраняется между перезапусками (том `tor-data`). Он меняется только если
удалить этот том.

---

## Шаг 5. TURN для звонков

Без этого шага сообщения работают, а **звонки — нет**: в режиме Tor приложение
не начинает звонок без ретранслятора, чтобы не раскрыть IP собеседнику.

Tor уже создал второй onion-адрес — для coturn. Передайте его релею, чтобы тот
отдавал его приложениям вместе с кредами:

```bash
TURN_ONION=$(docker compose exec -T tor cat /var/lib/tor/aegis-turn/hostname)
echo "$TURN_ONION"
sed -i "s/^AEGIS_TURN_ONION=.*/AEGIS_TURN_ONION=$TURN_ONION/" .env
docker compose up -d relay
```

Проверка — ответ должен быть JSON с полями `onion`, `username`, `credential`
(а не `404`):

```bash
docker compose exec -T relay curl -fsS http://127.0.0.1:8080/v1/turn
```

Креды эфемерные (по умолчанию живут 1 час), секрет TURN приложениям не
раскрывается. Вручную в приложении ничего вводить не нужно.

---

## Шаг 6. Проверка

**Состояние сервисов:**

```bash
docker compose ps                                                     # relay, coturn, tor — healthy
docker compose exec -T relay curl -fsS http://127.0.0.1:8080/v1/health
# {"status":"ok","service":"aegis-relay","version":"0.1.0","queued":0}
docker compose exec -T relay curl -fsS http://127.0.0.1:8080/v1/params
# {"v":1,"directory":true,"alias":false,"powBits":20,...}
```

**Доступность через Tor снаружи** — с любой другой машины, где есть Tor:

```bash
sudo apt-get install -y tor          # поднимет SOCKS-прокси на 127.0.0.1:9050
curl --socks5-hostname 127.0.0.1:9050 http://<onion-адрес-релея>:443/v1/health
```

Обратите внимание: `http://` и порт `443`. Внутри onion-сервиса релей говорит по
обычному HTTP, шифрование и подлинность обеспечивает сам Tor. Сразу после
первого запуска публикация onion-адреса в сети Tor может занять несколько минут.

**Порты наружу не открыты** (в режиме Onion так и должно быть):

```bash
sudo ss -tulpn | grep -E 'docker-proxy|:8080|:3478' || echo "наружу ничего не опубликовано"
```

---

## Шаг 7. Подключение приложения

1. Соберите приложение по инструкции из репозитория `aegis-client`, указав
   onion-адрес релея (README клиента, «Шаг 3. Адрес вашего сервера»):

   ```bash
   ./gradlew :app:assembleDebug -Paegis.defaultRelayOnion=<onion-адрес-релея>
   ```

   Или установите приложение без адреса и введите его вручную:
   **Настройки → Сеть и Tor → Адрес релея** (порт указывать не нужно).

2. В приложении нажмите **Проверить достижимость через Tor**.

3. Все, кто должен переписываться между собой, должны использовать **один и тот
   же** сервер: федерации между серверами нет.

Onion-адрес — публичная информация, как доменное имя: его знание не даёт доступа
к переписке. Но любой, кто его знает, может обращаться к API сервера (см.
ограничения про злоупотребления).

---

## Клирнет-профиль

Нужен, только если часть пользователей будет работать с **выключенным Tor**.
Профиль добавляет к основному стеку:

| Сервис | Что делает | Порты наружу |
|---|---|---|
| `caddy` | HTTPS-фронт → `relay:8080` (тот же релей, та же база). Сертификат Let's Encrypt выпускается и продлевается автоматически | `80/tcp` (выпуск сертификата и редирект), `443/tcp` |
| `coturn` | Тот же экземпляр, что за onion, с конфигом `docker/turn/turnserver.clearnet.conf`: STUN, TURN, TURNS | `3478/udp`, `3478/tcp`, `5349/tcp` |
| `turn-certs` | Копирует сертификат Caddy для coturn и даёт coturn перечитать его при продлении | нет |

Onion-доступ при этом не меняется. Пользователи с Tor и без Tor видят сообщения
друг друга и могут созваниваться: обе стороны получают аллокации на одном
coturn, и пересылка между ними идёт внутри сервера.

**Чем платят пользователи без Tor:** сервер видит их реальный IP и может
сопоставить его с адресами ящиков; собеседник при звонке видит IP. Шифрование не
меняется. Журналы адресов не пишутся: у Caddy нет журнала доступа, журнал coturn
выключен, релей адресов клиентов не получает (Caddy вырезает `X-Forwarded-For`
и подобные заголовки).

### 1. DNS

Создайте A-запись домена (в примерах — `relay.example.com`) на IP сервера.
**AAAA-записи быть не должно** (или IPv6 должен работать на сервере): Let's
Encrypt предпочитает IPv6, а профиль публикует порты только на IPv4.

```bash
dig +short A relay.example.com       # → IP вашего сервера
dig +short AAAA relay.example.com    # → пусто
```

### 2. Файрвол

```bash
sudo ufw allow 80,443/tcp   comment 'AEGIS HTTPS (Caddy, Lets Encrypt)'
sudo ufw allow 3478/udp     comment 'AEGIS STUN/TURN'
sudo ufw allow 3478/tcp     comment 'AEGIS TURN/TCP'
sudo ufw allow 5349/tcp     comment 'AEGIS TURNS'
```

Если у хостинга есть свой сетевой файрвол (облачный), откройте те же порты и
там. Диапазон relay-портов coturn (49152–51152) открывать **не нужно** — он
внутренний.

> Docker публикует порты в обход правил ufw. Закрыть опубликованный порт
> командой `ufw deny` нельзя — для этого отключают сам профиль (см. «Откат»).

### 3. .env

Замените `relay.example.com` на свой домен:

```bash
cd /opt/aegis/aegis-server
cat >> .env <<'EOF'
AEGIS_RELAY_DOMAIN=relay.example.com
AEGIS_TURN_PUBLIC_URIS=stun:relay.example.com:3478,turn:relay.example.com:3478?transport=udp,turn:relay.example.com:3478?transport=tcp,turns:relay.example.com:5349?transport=tcp
# Чтобы обычные команды `docker compose ...` всегда учитывали профиль:
COMPOSE_FILE=docker-compose.yml:docker-compose.clearnet.yml
EOF
```

- В `AEGIS_TURN_PUBLIC_URIS` хост должен совпадать с доменом релея: адреса на
  чужих доменах приложение отбрасывает.
- Строки, добавленные через `cat >>`, идут после пустых значений из
  `.env.example` и переопределяют их. Аккуратнее — отредактировать
  существующие строки в редакторе (`nano .env`).
- Если `AEGIS_RELAY_DOMAIN` или `AEGIS_TURN_PUBLIC_URIS` не заданы, запуск
  остановится с понятной ошибкой.

### 4. Запуск

```bash
docker compose up -d --build
docker compose ps        # caddy, coturn, relay, tor, turn-certs — Up
```

Caddy получает сертификат в первые секунды (нужны DNS и открытые 80/443).
Как только сертификат появится, `turn-certs` перезапустит coturn уже с TURNS —
это видно в `docker compose logs turn-certs`.

### 5. Проверки

```bash
# Сертификат выпущен:
docker compose logs caddy | grep -iE 'certificate obtained|renew'
echo | openssl s_client -connect relay.example.com:443 -servername relay.example.com 2>/dev/null \
  | openssl x509 -noout -issuer -enddate

# Релей по HTTPS — тот же, что за onion; в /v1/turn появилось поле uris:
curl -fsS https://relay.example.com/v1/health
curl -fsS https://relay.example.com/v1/turn | grep -o '"uris":\[[^]]*\]'

# TURNS отвечает с сертификатом:
echo | openssl s_client -connect relay.example.com:5349 -servername relay.example.com 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

Главная проверка — пересылка между «onion»- и клирнет-аллокацией и отказ
пересылать куда-либо наружу. На сервере:

```bash
python3 scripts/turn-relay-probe.py --secret "$(sed -n 's/^AEGIS_TURN_SECRET=//p' .env)" \
    --a tcp:172.28.7.10:3478 --b udp:relay.example.com:3478
# Ожидается: OK relay↔relay в обе стороны, 403 для публичного, частного,
# служебного адреса и loopback, «РЕЗУЛЬТАТ: РАБОТАЕТ».
```

С вашего компьютера (проверяет ещё файрвол и сертификат TURNS; секрет не
оставляйте в истории оболочки на чужих машинах):

```bash
python3 scripts/turn-relay-probe.py --secret '<AEGIS_TURN_SECRET>' \
    --a tcp:relay.example.com:3478 --b tls:relay.example.com:5349
python3 scripts/stun-probe.py relay.example.com:3478    # адрес клиента не подменяется Docker
```

### 6. Приложение

- При сборке клиента укажите `aegis.defaultRelayHttps=https://relay.example.com`
  (README клиента, «Шаг 3»), либо пользователь вводит адрес в **Настройки →
  Сеть и Tor → Адрес релея → HTTPS**.
- Если используете подписанный конфиг — переподпишите его с `--relay-https` и
  бо́льшим `--version` (см. [«Подписанный конфиг»](#подписанный-конфиг)).
- Пины SPKI необязательны; если включаете — пиньте корни Let's Encrypt
  (ISRG Root X1 и X2), а не сертификат сервера (README клиента, «Пины SPKI»).

### 7. Откат

```bash
sed -i '/^COMPOSE_FILE=/d;/^AEGIS_TURN_PUBLIC_URIS=/d;/^AEGIS_STUN_PUBLIC=/d' .env
docker compose -f docker-compose.yml up -d --build --remove-orphans
sudo ufw delete allow 80,443/tcp; sudo ufw delete allow 3478/udp
sudo ufw delete allow 3478/tcp;   sudo ufw delete allow 5349/tcp
```

Onion-доступ, данные и onion-ключи это не затрагивает. Пользователи с
выключенным Tor перестанут подключаться, пока не включат Tor.

---

## Подписанный конфиг

Необязательная функция. Сервер раздаёт приложениям актуальные адреса
(`GET /v1/config`), и при смене onion-адреса не нужно пересобирать APK.
Документ подписывается **офлайн-ключом Ed25519**; закрытый ключ на сервер **не
попадает**. Приложение проверяет подпись публичным ключом, вшитым при сборке, —
поэтому даже взломанный сервер не может подсунуть чужой адрес.

**1. Ключ (один раз, на доверенной машине, лучше офлайн)** — нужен Rust 1.97.0
и клон этого репозитория:

```bash
cargo run --release --features tools --bin aegis-config-sign -- keygen
# PRIVATE_KEY_HEX=...   ← хранить строго офлайн, НЕ на сервере и НЕ в git
# PUBLIC_KEY_HEX=...    ← вшить в приложение при сборке
```

**2. Публичный ключ — в сборку приложения** (`aegis-client`):

```properties
aegis.relayConfigPubkey=<PUBLIC_KEY_HEX>
```

**3. Подпись адресов.** Инструмент принимает закрытый ключ аргументом — чтобы
ключ не остался в истории оболочки, прочитайте его в переменную:

```bash
read -rs AEGIS_SIGN_KEY        # вставьте PRIVATE_KEY_HEX и нажмите Enter (ввод не отображается)
cargo run --release --features tools --bin aegis-config-sign -- sign \
    --key "$AEGIS_SIGN_KEY" \
    --relay <onion-адрес-релея> \
    --turn <onion-адрес-turn> --turn-port 3478 \
    --version 1 --min-app 2
unset AEGIS_SIGN_KEY
# → строки AEGIS_CONFIG_DOC=... и AEGIS_CONFIG_SIG=...
```

Дополнительные флаги: `--relay-https https://relay.example.com` — HTTPS-адрес
того же релея (только при включённом клирнет-профиле); `--https-pin
sha256/<base64>` — пины SPKI (можно повторять).

**4. На сервере** вставьте обе строки в `.env` (заменив пустые
`AEGIS_CONFIG_DOC=` и `AEGIS_CONFIG_SIG=`) и перезапустите релей:

```bash
docker compose up -d relay
docker compose exec -T relay curl -fsS http://127.0.0.1:8080/v1/config   # {"doc":...,"sig":...}
```

**Смена адреса:** повторите шаг 3 с **бо́льшим** `--version` — приложение
отвергает документ со старой версией (защита от отката). Без
`AEGIS_CONFIG_DOC`/`AEGIS_CONFIG_SIG` маршрут отвечает `404`, и приложение
пользуется вшитым при сборке адресом.

---

## Публичный STUN

Файл `docker-compose.stun.yml` и переменная `AEGIS_STUN_PUBLIC` оставлены для
старых версий клиента с переключателем «медиапоток через Tor». **Клиенту 0.4.2
они не нужны**: для режима без Tor он берёт STUN/TURN из клирнет-профиля.
`docker-compose.stun.yml` нельзя подключать вместе с клирнет-профилем — оба
публикуют `3478/udp`.

Если всё же включаете его (без клирнет-профиля):

```bash
sudo ufw allow 3478/udp comment 'AEGIS STUN'
echo 'AEGIS_STUN_PUBLIC=<домен-или-IP-сервера>:3478' >> .env
echo 'COMPOSE_FILE=docker-compose.yml:docker-compose.stun.yml' >> .env
docker compose up -d --build      # --build обязателен
docker compose exec -T relay curl -fsS http://127.0.0.1:8080/v1/turn | grep -o '"stun":"[^"]*"'
```

**Обязательная проверка подмены адреса** (относится и к клирнет-профилю).
Запускайте **не с сервера и не из его сети**:

```bash
python3 scripts/stun-probe.py <домен-или-IP-сервера>:3478
```

- `РЕЗУЛЬТАТ: РАБОТАЕТ` — сервер видит ваш настоящий внешний IP (сверьте с
  `curl https://api.ipify.org`).
- `РЕЗУЛЬТАТ: СЛОМАНО` — вернулся приватный адрес (`172.28.x.x`, `10.x.x.x`):
  UDP-порт обслуживает `userland-proxy` Docker. Добавьте
  `{"userland-proxy": false}` в `/etc/docker/daemon.json` и выполните
  `sudo systemctl restart docker`.
- `сервер не ответил` — порт закрыт файрволом или стек поднят без overlay-файла.

---

## Настройки .env

Полные пояснения — в [`.env.example`](.env.example). Значения вне допустимых
пределов релей молча приводит к ближайшей границе.

**Основные и хранение**

| Переменная | По умолчанию | Пределы | Назначение |
|---|---|---|---|
| `AEGIS_BIND` | `0.0.0.0:8080` в контейнере (`127.0.0.1:8080` вне Docker) | — | адрес HTTP внутри контейнера; наружу не публикуется |
| `AEGIS_DB` | `/data/aegis-relay.db` | — | путь к SQLite |
| `AEGIS_MAX_BODY_BYTES` | `65536` | 256 Б … 4 МиБ | максимальный размер тела запроса (кроме вложений) |
| `AEGIS_MAX_QUEUE` | `1000` | 1 … 1 000 000 | максимум конвертов в одном ящике |
| `AEGIS_MAX_TOTAL_MESSAGES` | `200000` | 1 000 … 100 000 000 | максимум конвертов во всей базе |
| `AEGIS_MAX_TOTAL_BYTES` | `536870912` (512 МиБ) | 1 МиБ … 1 ТиБ | максимальный объём конвертов |
| `AEGIS_TTL_SECS` | `604800` (7 суток) | 60 с … 7 суток | срок хранения конвертов |
| `AEGIS_MAX_WAIT_SECS` | `30` | 1 … 120 | максимальное ожидание long-poll |
| `AEGIS_POLL_LIMIT` | `256` | 1 … 10 000 | конвертов за один запрос |
| `AEGIS_BLOB_MAX_BYTES` | `12582912` (12 МиБ) | 64 КиБ … 32 МиБ | максимальный размер одного вложения |
| `AEGIS_MAX_BLOBS` | `2000` | 1 … 1 000 000 | максимум вложений |
| `AEGIS_MAX_BLOB_BYTES_TOTAL` | `1073741824` (1 ГиБ) | 1 МиБ … 1 ТиБ | максимальный объём вложений |
| `RUST_LOG` | `aegis_relay=info,tower_http=info` | — | уровень журнала |

**Звонки (TURN)**

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `AEGIS_TURN_SECRET` | — (**обязательно**) | общий секрет релея и coturn: `openssl rand -hex 32` |
| `AEGIS_TURN_ONION` | пусто | onion-адрес coturn (шаг 5) |
| `AEGIS_TURN_PORT` | `3478` | порт coturn на onion |
| `AEGIS_TURN_TTL_SECS` | `3600` | срок жизни кредов (60 с … 7 суток) |
| `AEGIS_TURN_REALM` | `aegis` | realm coturn |
| `AEGIS_TURN_PUBLIC_URIS` | пусто | клирнет STUN/TURN/TURNS для клиентов без Tor |
| `AEGIS_STUN_PUBLIC` | пусто | устаревший публичный STUN (см. [«Публичный STUN»](#публичный-stun)) |

`GET /v1/turn` работает, когда задан секрет **и** хотя бы один адрес
(`AEGIS_TURN_ONION` или `AEGIS_TURN_PUBLIC_URIS`); иначе — `404`.

**Клирнет-профиль**

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `AEGIS_RELAY_DOMAIN` | пусто | домен HTTPS-фронта (обязателен для профиля) |
| `AEGIS_TURN_DOMAIN` | = `AEGIS_RELAY_DOMAIN` | домен сертификата TURNS |
| `AEGIS_HTTPS_BIND` | `0.0.0.0` | адрес хоста для портов 80/443 |
| `AEGIS_TURN_BIND` | `0.0.0.0` | адрес хоста для портов 3478/5349 |
| `AEGIS_STUN_BIND` | `0.0.0.0` | адрес хоста для устаревшего публичного STUN |
| `COMPOSE_FILE` | — | список compose-файлов, например `docker-compose.yml:docker-compose.clearnet.yml` |

**Подписанный конфиг**

| Переменная | Назначение |
|---|---|
| `AEGIS_CONFIG_DOC`, `AEGIS_CONFIG_SIG` | документ и подпись от `aegis-config-sign` (пусто — `/v1/config` отвечает `404`) |

**Каталог контактов и ники**

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `AEGIS_DIRECTORY_ENABLED` | `1` | приватный каталог для удалённого добавления контактов (`0` — выключить) |
| `AEGIS_MAX_DIRECTORY` | `100000` | максимум записей каталога |
| `AEGIS_DIRECTORY_MAX_BYTES` | `16384` | размер одной записи (512 Б … 256 КиБ) |
| `AEGIS_DIRECTORY_MAX_TTL_SECS` | `7776000` (90 суток) | максимальный срок записи (1 час … 365 суток) |
| `AEGIS_ALIAS_ENABLED` | `0` | публичные `@ники`. **Выключены сознательно:** пространство ников перечислимо словарём. С клиентом 0.4.2 не работают |
| `AEGIS_MAX_ALIASES` | `100000` | максимум ников |
| `AEGIS_POW_BITS` | `20` | сложность proof-of-work на маршрутах ников (0 … 32) |

После изменения `.env` примените его: `docker compose up -d` (Compose
пересоздаст контейнеры, у которых изменились настройки).

---

## Данные и резервные копии

| Том | Что хранит | Нужен ли бэкап |
|---|---|---|
| `relay-data` | SQLite: конверты (не старше 7 суток), вложения, prekeys, каталог | по желанию — там только шифртекст |
| `tor-data` | **закрытые ключи onion-адресов** | да, если адрес должен остаться прежним |
| `caddy-data`, `caddy-config`, `turn-certs` | сертификаты (клирнет-профиль) | нет — Caddy выпустит заново |

Docker добавляет к именам томов префикс — имя каталога проекта:
`aegis-server_relay-data`, `aegis-server_tor-data` (проверьте:
`docker volume ls | grep aegis`).

Схема базы создаётся и обновляется автоматически при старте — отдельных миграций
нет. Просроченные данные удаляются сами.

**Бэкап:**

```bash
cd /opt/aegis/aegis-server
docker compose stop relay
docker run --rm -v aegis-server_relay-data:/data -v "$PWD":/backup debian:bookworm-slim \
    tar czf /backup/relay-data-$(date +%F).tgz --numeric-owner -C /data .
docker compose start relay

docker run --rm -v aegis-server_tor-data:/data -v "$PWD":/backup debian:bookworm-slim \
    tar czf /backup/tor-data-$(date +%F).tgz --numeric-owner -C /data .
sudo chown "$USER": tor-data-*.tgz relay-data-*.tgz && chmod 600 tor-data-*.tgz
```

> Архив `tor-data` содержит закрытые ключи onion-адресов: кто его получит, сможет
> выдавать себя за ваш сервер. Храните его как секрет и не оставляйте в
> каталоге проекта.

**Восстановление на новом сервере** (после шагов 1–3, вместо шага 4):

```bash
docker compose up --no-start --build     # собрать образы и создать тома, ничего не запуская
docker run --rm -v aegis-server_tor-data:/data -v "$PWD":/backup debian:bookworm-slim \
    tar xzf /backup/tor-data-YYYY-MM-DD.tgz --numeric-owner -C /data
# аналогично для relay-data, если нужно
docker compose up -d
```

Не забудьте перенести и `.env` (в нём секрет TURN и `AEGIS_TURN_ONION`).

**Смена onion-адреса** (например, при компрометации ключей): остановите стек,
удалите том `tor-data` (`docker compose down && docker volume rm
aegis-server_tor-data`), запустите снова, обновите `AEGIS_TURN_ONION` (шаг 5) и
доставьте новый адрес пользователям — новой сборкой приложения или подписанным
конфигом с бо́льшим `--version`.

---

## Обновление

```bash
cd /opt/aegis/aegis-server
git pull
docker compose up -d --build
docker compose ps
```

Onion-адреса и данные сохраняются: тома не пересоздаются. **Никогда не
выполняйте `docker compose down -v`** — ключ `-v` удаляет тома вместе с
onion-адресами и очередью сообщений.

Откат на предыдущую версию: `git checkout <коммит>` и снова
`docker compose up -d --build`.

---

## Логи и мониторинг

```bash
docker compose logs -f relay        # релей
docker compose logs -f tor          # Tor: подключение и публикация onion
docker compose logs -f coturn       # TURN (в клирнет-профиле журнал coturn выключен)
docker compose logs -f caddy        # сертификаты (клирнет-профиль)
```

- Содержимого сообщений и идентификаторов пользователей в журналах нет. Уровень
  журнала — `RUST_LOG` в `.env`.
- Журналы контейнеров ротируются автоматически (10 МБ × 5 файлов на сервис).
- Загрузка — поле `queued` в `GET /v1/health`.
- Состояние — `docker compose ps` (у `relay`, `coturn`, `tor` есть проверки
  здоровья).

---

## API

Краткий список. Полное описание протокола, форматов и модели доверия —
[`PROTOCOL.md`](PROTOCOL.md).

| Метод и путь | Назначение |
|---|---|
| `GET /v1/health` | состояние релея и число конвертов в очереди |
| `GET /v1/params` | возможности релея (каталог, ники, сложность PoW) |
| `POST /v1/mailbox/{id}` | положить конверт в ящик |
| `GET /v1/mailbox/{id}?after={seq}&wait={sec}` | забрать конверты (long-poll) |
| `POST /v1/mailbox/{id}/ack` | подтвердить получение |
| `PUT`, `GET /v1/prekeys/{id}` | публичные prekey-бандлы Signal |
| `PUT`, `GET`, `DELETE /v1/blob/{id}` | зашифрованные вложения и голосовые |
| `PUT`, `GET`, `DELETE /v1/directory/{index}` | приватный каталог удалённого добавления контактов |
| `PUT`, `GET /v1/alias/{index}` | публичные ники (по умолчанию выключены; требуют PoW) |
| `GET /v1/turn` | эфемерные креды TURN |
| `GET /v1/config` | подписанный конфиг с адресами сервера |

---

## Разработка и тесты

Нужен Rust **1.97.0** (закреплён в `rust-toolchain.toml`, rustup поставит его
сам).

```bash
cargo test --locked --features tools        # 72 теста релея + 4 теста aegis-config-sign
cargo clippy --all-targets --locked --features tools
cargo fmt --all --check

# Локальный запуск (слушает 127.0.0.1:8080, база aegis-relay.db в текущем каталоге):
cargo run --release
curl -s http://127.0.0.1:8080/v1/health
```

Тесты не требуют сети и Docker. Проверить, что образ собирается:
`docker build -t aegis-relay:dev .`

Изменения протокола делаются согласованно с клиентом (`aegis-client`) и
отражаются в [`PROTOCOL.md`](PROTOCOL.md).

---

## Воспроизводимые сборки

Версия Rust закреплена в `rust-toolchain.toml` и в базовом образе `Dockerfile`
(`rust:1.97.0-bookworm`), зависимости — в `Cargo.lock` (сборка с `--locked`).

```bash
scripts/verify-reproducible-build.sh                         # дважды собрать релей и сравнить SHA-256
AEGIS_VERIFY_DOCKER=1 scripts/verify-reproducible-build.sh   # + сравнить с бинарником из Docker
scripts/generate-sbom.sh                                     # список зависимостей → docs/sbom/
```

Подробности — [`docs/reproducible-builds.md`](docs/reproducible-builds.md).

---

## Структура репозитория

| Путь | Назначение |
|---|---|
| `src/main.rs` | запуск релея, фоновая очистка просроченных данных |
| `src/api.rs` | HTTP-маршруты и их тесты |
| `src/store.rs` | хранилище SQLite: ящики, вложения, prekeys, лимиты |
| `src/config.rs` | чтение настроек из переменных окружения |
| `src/directory.rs` | каталог контактов и публичные ники |
| `src/turn.rs` | креды TURN (TURN REST API, HMAC) |
| `src/pow.rs` | proof-of-work для маршрутов ников |
| `src/bin/config_sign.rs` | офлайн-инструмент подписи конфига (`aegis-config-sign`) |
| `docker-compose.yml` | основной стек: relay, coturn, tor |
| `docker-compose.clearnet.yml` | клирнет-профиль: caddy, публичные порты coturn, turn-certs |
| `docker-compose.stun.yml` | устаревший публичный STUN |
| `docker/tor/` | образ и `torrc` для onion-адресов |
| `docker/turn/` | конфиги coturn (onion и клирнет) |
| `docker/caddy/` | `Caddyfile` и скрипт передачи сертификата в coturn |
| `scripts/` | проверки TURN/STUN, воспроизводимость, SBOM |
| `docs/` | воспроизводимые сборки, SBOM |
| `PROTOCOL.md` | протокол клиент↔сервер и модель доверия |
| `.github/workflows/` | CI: формат, clippy, тесты, release-сборка, Docker; проверка воспроизводимости |

Ссылки вида «§7.6», «§12.2», «P9» в комментариях и документах указывают на
разделы исходного технического задания и этапы разработки. Само ТЗ не
публикуется — поведение описано в этом README и в `PROTOCOL.md`.

---

## Известные ограничения

По результатам аудита кода от 01.11.2026. Подробно — [`PROTOCOL.md`](PROTOCOL.md), §6.

- **Доступность.** Ограничения частоты запросов нет, а при переполнении
  глобальных потолков вытесняются самые старые конверты, вложения и записи
  каталога **по всей базе** — анонимный клиент дешёвым потоком запросов может
  удалить чужие недоставленные данные.
- **Метаданные.** Оператор сервера может связать ящики одного клиента и
  восстановить псевдонимный граф «кто-кому»; открытые поля конверта выдают тип
  трафика и число устройств адресата (`PROTOCOL.md`, §1).
- **Хранение.** Таблица `mailbox_seq` (список всех когда-либо использованных
  идентификаторов ящиков со счётчиком сообщений) не очищается никогда — ни по
  сроку 7 суток, ни по глобальным потолкам.
- **Мелочи.** `GET /v1/health` отдаёт глобальное число конвертов в очереди;
  `PUT /v1/prekeys/{id}` перезаписывает любой, кто знает id; Ed25519
  проверяется `verify`, а не `verify_strict`; PoW — 20 бит; в `torrc` нет
  `HiddenServicePoWDefensesEnabled`; образы не закреплены по digest; секрет TURN
  передаётся coturn аргументом командной строки (`docker-compose.yml`), а
  `aegis-config-sign` принимает закрытый ключ аргументом.
- **Совместимость с клиентом 0.4.2.** Публикация `@ника` не работает: клиент
  отправляет ключ в поле `ed25519Hex`, а релей требует `ed25519`.

---

## Решение проблем

| Симптом | Причина и решение |
|---|---|
| `required variable AEGIS_TURN_SECRET is missing a value` | Не задан секрет TURN — [шаг 3](#шаг-3-код-и-настройка-env) |
| Сборка образа падает с `signal: 9, SIGKILL` или `out of memory` | Не хватает памяти для компиляции — добавьте swap ([шаг 1.5](#15-swap-если-озу-меньше-2-гб)) |
| `relay` в состоянии `unhealthy` | `docker compose logs relay`; проверьте, что том `/data` доступен на запись |
| `tor` долго не становится `healthy` | `docker compose logs tor` — дошёл ли Tor до `Bootstrapped 100%`; проверьте точность часов (шаг 1.6) и исходящий интернет |
| Приложение не подключается к релею | Верен ли onion-адрес в приложении; работает ли проверка через Tor из [шага 6](#шаг-6-проверка); после первого запуска подождите несколько минут |
| `/v1/turn` отвечает `404` | Не задан `AEGIS_TURN_SECRET` или ни один адрес TURN — [шаг 5](#шаг-5-turn-для-звонков) |
| Звонки не соединяются | `docker compose ps coturn` (healthy?); `AEGIS_TURN_ONION` совпадает с `/var/lib/tor/aegis-turn/hostname`; для клирнета — `scripts/turn-relay-probe.py` |
| Onion-адрес сменился | Удалялся том `tor-data` — восстановите его из бэкапа |
| `network … needs to be recreated` или конфликт подсети | Подсеть `172.28.7.0/24` занята на хосте (`ip route \| grep 172.28`). Меняйте её **одновременно** в `docker-compose.yml` (`subnet` и все `ipv4_address`) и в обоих `docker/turn/turnserver*.conf` (`relay-ip`, `allowed-peer-ip`), затем `docker compose down && docker compose up -d` |
| Caddy не выпускает сертификат | A-запись ведёт на сервер, AAAA нет, порт `80/tcp` открыт снаружи (Let's Encrypt проверяет по HTTP), в том числе в облачном файрволе |
| Клиент без Tor: «релей недоступен» | `curl -fsS https://<домен>/v1/health` с вашего компьютера; `docker compose logs caddy`; DNS и порты 80/443 |
| TURNS (5349) не отвечает | `docker compose logs turn-certs` — скопирован ли сертификат; затем `docker compose restart coturn` |
| Очередь (`queued`) растёт | Просроченное удаляется само через 7 суток; если растёт быстро — возможен поток мусорных запросов (см. ограничения) |

---

## Лицензия

Код распространяется по лицензии **GNU GPL v3.0 или новее** — см. [`LICENSE`](LICENSE).

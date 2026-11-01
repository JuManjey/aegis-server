# Tor-демон, публикующий AEGIS relay как Onion Service v3 (§7.2/§12.2).
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor \
    && rm -rf /var/lib/apt/lists/*
COPY torrc /etc/tor/torrc
# Запускаемся от root: tor прочитает конфиг и сам сбросит привилегии на
# debian-tor (директива `User` в torrc), заодно выставив владельца DataDirectory.
CMD ["tor", "-f", "/etc/tor/torrc"]

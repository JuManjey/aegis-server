#!/usr/bin/env python3
"""Проверка coturn для собеседников в РАЗНЫХ режимах сети (Tor ВКЛ ↔ Tor ВЫКЛ).

Что проверяется:
  1. relay↔relay: две аллокации на одном coturn — «A» (как у клиента через onion:
     TCP к внутреннему адресу coturn) и «B» (как у клиента без Tor: UDP или TCP к
     опубликованному порту) — пересылают друг другу данные в обе стороны. Именно
     так соединяются собеседник с Tor (у него только relay-кандидат) и собеседник
     без Tor.
  2. coturn не ретранслирует наружу: разрешения на публичный, частный и служебный
     адрес (в том числе адрес метаданных облака) отклоняются с 403.

Запуск на сервере (адрес A — внутренний адрес coturn в compose-сети, он доступен
с хоста; адрес B — публичный домен):

  python3 scripts/turn-relay-probe.py --secret "$AEGIS_TURN_SECRET" \\
      --a tcp:172.28.7.10:3478 --b udp:relay.example.com:3478

B лучше запускать и снаружи (с рабочей машины) — тогда проверяется ещё и
публикация порта и файрвол; `--b tls:relay.example.com:5349` проверяет TURNS
вместе с сертификатом Let's Encrypt. Креды выводятся из общего секрета так же, как это
делает релей в GET /v1/turn (TURN REST API, coturn use-auth-secret). Только
стандартная библиотека Python.
"""
import argparse
import base64
import hashlib
import hmac
import secrets
import socket
import ssl
import struct
import sys
import time

MAGIC = 0x2112A442

ALLOCATE = 0x0003
CREATE_PERMISSION = 0x0008
SEND_INDICATION = 0x0016
DATA_INDICATION = 0x0017

ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_XOR_PEER_ADDRESS = 0x0012
ATTR_DATA = 0x0013
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_REQUESTED_TRANSPORT = 0x0019

SUCCESS_CLASS = 0x0100
ERROR_CLASS = 0x0110


def attr(kind: int, value: bytes) -> bytes:
    return struct.pack(">HH", kind, len(value)) + value + b"\x00" * (-len(value) % 4)


def xor_address(ip: str, port: int) -> bytes:
    raw = socket.inet_aton(ip)
    xip = bytes(b ^ c for b, c in zip(raw, struct.pack(">I", MAGIC)))
    return struct.pack(">BBH", 0, 1, port ^ (MAGIC >> 16)) + xip


def parse_xor_address(value: bytes) -> tuple[str, int]:
    port = struct.unpack(">H", value[2:4])[0] ^ (MAGIC >> 16)
    ip = bytes(b ^ c for b, c in zip(value[4:8], struct.pack(">I", MAGIC)))
    return socket.inet_ntoa(ip), port


def parse(message: bytes) -> tuple[int, bytes, dict[int, bytes]]:
    msg_type, length, cookie, txn = struct.unpack(">HHI12s", message[:20])
    if cookie != MAGIC:
        raise ValueError("не STUN-сообщение")
    attrs: dict[int, bytes] = {}
    offset = 20
    while offset + 4 <= 20 + length:
        kind, size = struct.unpack(">HH", message[offset:offset + 4])
        attrs.setdefault(kind, message[offset + 4:offset + 4 + size])
        offset += 4 + size + (-size % 4)
    return msg_type, txn, attrs


class TurnClient:
    """Минимальный TURN-клиент (RFC 5766) поверх UDP или TCP — только то, что нужно проверке."""

    def __init__(self, name: str, target: str, username: str, password: str, timeout: float,
                 cafile: str | None = None):
        transport, host, port = target.split(":")
        if transport not in ("udp", "tcp", "tls"):
            raise ValueError(f"{name}: транспорт {transport!r} — ожидается udp, tcp или tls")
        self.name = name
        self.tcp = transport in ("tcp", "tls")
        self.username = username
        self.password = password
        self.realm = b""
        self.nonce = b""
        self.key = b""
        family_addr = socket.getaddrinfo(host, int(port), socket.AF_INET)[0][4]
        if self.tcp:
            self.sock = socket.create_connection(family_addr, timeout=timeout)
            if transport == "tls":
                # TURNS (5349): цепочка и имя проверяются, как у клиента WebRTC.
                context = ssl.create_default_context(cafile=cafile)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.sock = context.wrap_socket(self.sock, server_hostname=host)
                print(f"{name}: TLS {self.sock.version()}, сертификат для {host} принят")
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect(family_addr)
        self.sock.settimeout(timeout)
        self.relayed: tuple[str, int] | None = None

    # --- транспорт -----------------------------------------------------------

    def send_raw(self, data: bytes) -> None:
        if self.tcp:
            self.sock.sendall(data)
        else:
            self.sock.send(data)

    def recv_message(self) -> bytes:
        if not self.tcp:
            return self.sock.recv(65535)
        header = self._recv_exact(20)
        length = struct.unpack(">H", header[2:4])[0]
        return header + self._recv_exact(length)

    def _recv_exact(self, size: int) -> bytes:
        out = b""
        while len(out) < size:
            chunk = self.sock.recv(size - len(out))
            if not chunk:
                raise ConnectionError("соединение закрыто сервером")
            out += chunk
        return out

    # --- сообщения -----------------------------------------------------------

    def build(self, msg_type: int, attrs: bytes, txn: bytes, integrity: bool) -> bytes:
        if not integrity:
            return struct.pack(">HHI12s", msg_type, len(attrs), MAGIC, txn) + attrs
        auth = attr(ATTR_USERNAME, self.username.encode()) + attr(ATTR_REALM, self.realm) + attr(ATTR_NONCE, self.nonce)
        body = attrs + auth
        header = struct.pack(">HHI12s", msg_type, len(body) + 24, MAGIC, txn)
        mac = hmac.new(self.key, header + body, hashlib.sha1).digest()
        return header + body + attr(ATTR_MESSAGE_INTEGRITY, mac)

    def transact(self, msg_type: int, attrs: bytes) -> tuple[int, dict[int, bytes]]:
        txn = secrets.token_bytes(12)
        self.send_raw(self.build(msg_type, attrs, txn, integrity=bool(self.key)))
        while True:
            kind, resp_txn, resp_attrs = parse(self.recv_message())
            if resp_txn == txn:
                return kind, resp_attrs

    @staticmethod
    def error_code(attrs: dict[int, bytes]) -> int:
        value = attrs.get(ATTR_ERROR_CODE, b"\x00\x00\x00\x00")
        return (value[2] & 0x07) * 100 + value[3]

    def allocate(self) -> tuple[str, int]:
        transport = attr(ATTR_REQUESTED_TRANSPORT, struct.pack(">BBBB", 17, 0, 0, 0))
        kind, attrs = self.transact(ALLOCATE, transport)
        if kind == ALLOCATE | ERROR_CLASS and self.error_code(attrs) == 401:
            self.realm = attrs.get(ATTR_REALM, b"")
            self.nonce = attrs.get(ATTR_NONCE, b"")
            self.key = hashlib.md5(f"{self.username}:{self.realm.decode()}:{self.password}".encode()).digest()
            kind, attrs = self.transact(ALLOCATE, transport)
        if kind != ALLOCATE | SUCCESS_CLASS:
            raise RuntimeError(f"{self.name}: Allocate отклонён (код {self.error_code(attrs)})")
        self.relayed = parse_xor_address(attrs[ATTR_XOR_RELAYED_ADDRESS])
        return self.relayed

    def permit(self, ip: str) -> int:
        """0 — разрешение выдано, иначе код ошибки TURN (403 — запрещено политикой)."""
        kind, attrs = self.transact(CREATE_PERMISSION, attr(ATTR_XOR_PEER_ADDRESS, xor_address(ip, 0)))
        return 0 if kind == CREATE_PERMISSION | SUCCESS_CLASS else self.error_code(attrs)

    def send_to(self, peer: tuple[str, int], payload: bytes) -> None:
        attrs = attr(ATTR_XOR_PEER_ADDRESS, xor_address(*peer)) + attr(ATTR_DATA, payload)
        self.send_raw(self.build(SEND_INDICATION, attrs, secrets.token_bytes(12), integrity=False))

    def receive_data(self, deadline: float) -> bytes | None:
        while time.time() < deadline:
            try:
                kind, _, attrs = parse(self.recv_message())
            except socket.timeout:
                continue
            if kind == DATA_INDICATION:
                return attrs.get(ATTR_DATA)
        return None


def rest_credentials(secret: str, ttl: int = 3600) -> tuple[str, str]:
    username = f"{int(time.time()) + ttl}:relay-probe"
    password = base64.b64encode(hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()).decode()
    return username, password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--secret", required=True, help="AEGIS_TURN_SECRET (общий секрет релея и coturn)")
    parser.add_argument("--a", required=True, help="клиент «через onion»: tcp:<host>:<port>")
    parser.add_argument("--b", required=True, help="клиент «без Tor»: udp|tcp|tls:<host>:<port>")
    parser.add_argument("--cafile", help="свой корневой сертификат для tls: (только для тестов)")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    username, password = rest_credentials(args.secret)
    failures = 0
    a = TurnClient("A", args.a, username, password, args.timeout, args.cafile)
    b = TurnClient("B", args.b, username, password, args.timeout, args.cafile)
    relay_a = a.allocate()
    relay_b = b.allocate()
    print(f"A ({args.a}): relay-кандидат {relay_a[0]}:{relay_a[1]}")
    print(f"B ({args.b}): relay-кандидат {relay_b[0]}:{relay_b[1]}")

    for client, peer in ((a, relay_b), (b, relay_a)):
        code = client.permit(peer[0])
        if code:
            print(f"СЛОМАНО: {client.name} не получил разрешение на relay-адрес собеседника (код {code})")
            failures += 1

    for sender, receiver, peer in ((a, b, relay_b), (b, a, relay_a)):
        payload = f"aegis-relay-probe {sender.name}->{receiver.name} {secrets.token_hex(4)}".encode()
        received = None
        for _ in range(3):  # UDP может потерять пакет — повторяем
            sender.send_to(peer, payload)
            received = receiver.receive_data(time.time() + args.timeout)
            if received == payload:
                break
        if received == payload:
            print(f"OK: relay↔relay {sender.name} → {receiver.name}")
        else:
            print(f"СЛОМАНО: данные {sender.name} → {receiver.name} не дошли через coturn")
            failures += 1

    for ip, what in (("8.8.8.8", "публичный адрес"), ("192.168.1.1", "частная сеть"),
                     ("169.254.169.254", "метаданные облака"), ("127.0.0.1", "loopback")):
        code = a.permit(ip)
        if code == 403:
            print(f"OK: ретрансляция на {what} ({ip}) запрещена (403)")
        else:
            print(f"СЛОМАНО: разрешение на {what} ({ip}) — код {code or 'выдано'}; coturn — открытый прокси")
            failures += 1

    print("РЕЗУЛЬТАТ: РАБОТАЕТ" if failures == 0 else f"РЕЗУЛЬТАТ: ошибок {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

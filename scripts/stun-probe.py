#!/usr/bin/env python3
"""Проверка публичного STUN: возвращает ли сервер РЕАЛЬНЫЙ адрес спрашивающего.

Зачем нужен отдельный скрипт. Если Docker обслуживает опубликованный UDP-порт
через `docker-proxy`, адрес источника подменяется на адрес docker-шлюза, и STUN
начинает сообщать всем клиентам одинаковый бессмысленный адрес. Прямой путь
медиа при этом не строится, но НИ ОДНОЙ ошибки не появляется — ни в логах
сервера, ни в приложении. Единственный надёжный способ отличить рабочую
конфигурацию от сломанной — спросить сервер снаружи и сравнить ответ со своим
настоящим адресом.

Реализовано ровно то, что делает WebRTC: STUN Binding Request (RFC 5389) и
разбор XOR-MAPPED-ADDRESS из ответа.
"""
import os
import secrets
import socket
import struct
import sys

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020


def build_request(txn_id: bytes) -> bytes:
    """Binding Request без атрибутов — ровно то, что шлёт WebRTC при сборе ICE."""
    return struct.pack(">HHI12s", BINDING_REQUEST, 0, MAGIC_COOKIE, txn_id)


def parse_mapped_address(payload: bytes, txn_id: bytes) -> str | None:
    """Достаёт адрес спрашивающего из ответа. `None`, если ответ не Binding Success."""
    if len(payload) < 20:
        return None
    msg_type, length, cookie, resp_txn = struct.unpack(">HHI12s", payload[:20])
    if msg_type != BINDING_SUCCESS or cookie != MAGIC_COOKIE or resp_txn != txn_id:
        return None

    offset = 20
    end = min(len(payload), 20 + length)
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack(">HH", payload[offset:offset + 4])
        value = payload[offset + 4:offset + 4 + attr_len]
        # Атрибуты выровнены по 4 байта.
        offset += 4 + attr_len + (-attr_len % 4)

        if attr_type not in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS):
            continue
        if len(value) < 8 or value[1] != 0x01:  # 0x01 = IPv4
            continue
        port = struct.unpack(">H", value[2:4])[0]
        raw_ip = value[4:8]
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            # XOR со cookie (порт — со старшими 16 битами cookie).
            port ^= MAGIC_COOKIE >> 16
            raw_ip = bytes(b ^ c for b, c in zip(raw_ip, struct.pack(">I", MAGIC_COOKIE)))
        return f"{socket.inet_ntoa(raw_ip)}:{port}"
    return None


def probe(host: str, port: int, attempts: int = 3, timeout: float = 3.0) -> str | None:
    """Спрашивает сервер несколько раз: одиночная потеря UDP-пакета — норма."""
    for attempt in range(1, attempts + 1):
        txn_id = secrets.token_bytes(12)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendto(build_request(txn_id), (host, port))
                data, _ = sock.recvfrom(2048)
            except (socket.timeout, OSError) as exc:
                print(f"  попытка {attempt}/{attempts}: нет ответа ({exc})")
                continue
        mapped = parse_mapped_address(data, txn_id)
        if mapped:
            return mapped
        print(f"  попытка {attempt}/{attempts}: ответ получен, но это не Binding Success")
    return None


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("STUN_TARGET", "")
    if ":" not in target:
        print("использование: stun-probe.py <host>:<port>")
        return 2
    host, port_str = target.rsplit(":", 1)

    print(f"STUN Binding → {host}:{port_str}")
    mapped = probe(host, int(port_str))
    if mapped is None:
        print("РЕЗУЛЬТАТ: сервер не ответил — порт закрыт файрволом либо не слушается")
        return 1

    ip = mapped.rsplit(":", 1)[0]
    print(f"сервер сообщил наш адрес: {mapped}")

    private = (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("172.")  # грубо: покрывает docker-подсети 172.16–172.31
    )
    if private:
        print("РЕЗУЛЬТАТ: СЛОМАНО — адрес приватный, значит источник подменён")
        print("           (userland-proxy / SNAT). Прямой путь медиа не построится.")
        return 1
    print("РЕЗУЛЬТАТ: РАБОТАЕТ — адрес публичный, источник сохранён")
    return 0


if __name__ == "__main__":
    sys.exit(main())

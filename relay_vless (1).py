"""VMess AEAD over WebSocket relay for the X4G service.

The public filename is kept as relay_vless.py so existing deployments that import
that module continue to start. The wire protocol handled here is VMess AEAD,
using the UUID stored in main.LINKS as the user credential.
"""

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import secrets
import struct
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS, LINKS_LOCK, stats, hourly_traffic, connections, error_logs, logger,
    is_link_allowed, is_ip_allowed, save_state, log_activity, now_ir,
)

RELAY_BUF = 256 * 1024
CMD_KEY_SUFFIX = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"


def _kdf(key: bytes, *paths: bytes) -> bytes:
    out = hmac.new(b"VMess AEAD KDF", digestmod=hashlib.sha256)
    for path in paths:
        out = hmac.new(out.digest(), path, hashlib.sha256)
    return out.digest() if not paths else hmac.new(out.digest(), key, hashlib.sha256).digest()


def _kdf_correct(key: bytes, *paths: bytes) -> bytes:
    # KDF(key, p1, p2, ...) = HMAC(HMAC(...HMAC("VMess AEAD KDF", p1), p2)..., key)
    state = b"VMess AEAD KDF"
    for path in paths:
        state = hmac.new(state, path, hashlib.sha256).digest()
    return hmac.new(state, key, hashlib.sha256).digest()


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def _aes_cfb_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _aes_cfb_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _fnv1a(data: bytes) -> int:
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


def _uuid_bytes(uid: str) -> bytes:
    raw = uid.replace("-", "")
    if len(raw) != 32:
        raise ValueError("invalid UUID")
    return bytes.fromhex(raw)


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "unknown"


def _decode_address(buf: bytes, pos: int):
    if pos >= len(buf):
        raise ValueError("missing address type")
    addr_type = buf[pos]
    pos += 1
    if addr_type == 1:
        if pos + 4 > len(buf):
            raise ValueError("short IPv4 address")
        address = str(ipaddress.IPv4Address(buf[pos:pos + 4]))
        pos += 4
    elif addr_type == 2:
        if pos >= len(buf):
            raise ValueError("short domain length")
        length = buf[pos]
        pos += 1
        if pos + length > len(buf):
            raise ValueError("short domain address")
        address = buf[pos:pos + length].decode("utf-8", "strict")
        pos += length
    elif addr_type == 3:
        if pos + 16 > len(buf):
            raise ValueError("short IPv6 address")
        address = str(ipaddress.IPv6Address(buf[pos:pos + 16]))
        pos += 16
    else:
        raise ValueError("unknown address type")
    return address, pos


def _parse_command(command: bytes):
    if len(command) < 34 or command[0] != 1:
        raise ValueError("invalid VMess command header")
    pos = 1 + 16 + 16 + 1
    option = command[pos]
    pos += 1
    padding = command[pos] >> 4
    security = command[pos] & 0x0f
    pos += 1
    pos += 1  # reserved
    cmd = command[pos]
    pos += 1
    if cmd != 1:
        raise ValueError("UDP VMess requests are not supported by this relay")
    if pos + 2 > len(command):
        raise ValueError("missing destination port")
    port = int.from_bytes(command[pos:pos + 2], "big")
    pos += 2
    address, pos = _decode_address(command, pos)
    if pos + padding + 4 > len(command):
        raise ValueError("invalid VMess padding/checksum")
    pos += padding
    expected = int.from_bytes(command[pos:pos + 4], "big")
    if _fnv1a(command[:pos]) != expected:
        raise ValueError("VMess command checksum mismatch")
    return {
        "option": option, "security": security, "cmd": cmd, "port": port,
        "address": address, "iv": command[1:17], "key": command[17:33],
        "response_auth": command[33],
    }


async def parse_vless_header(chunk: bytes, uid: str | None = None):
    """Compatibility name retained for main imports; parses a VMess AEAD request."""
    if len(chunk) < 26:
        raise ValueError("VMess request is too short")
    # The AEAD authentication ID occupies the first 16 bytes. The encrypted
    # length follows it, then an 8-byte nonce and the encrypted command header.
    e_auth = chunk[:16]
    e_len = chunk[16:34]
    nonce = chunk[34:42]
    if len(nonce) != 8:
        raise ValueError("missing VMess nonce")
    # UUID is supplied by websocket_tunnel through the temporary attribute.
    uid = uid or getattr(parse_vless_header, "_uid", None)
    if not uid:
        raise ValueError("missing VMess UUID context")
    user_id = _uuid_bytes(uid)
    cmd_key = hashlib.md5(user_id + CMD_KEY_SUFFIX).digest()
    auth_key = _kdf_correct(cmd_key, b"AES Auth ID Encryption")[:16]
    auth_plain = _aes_ecb_decrypt(auth_key, e_auth)
    timestamp = int.from_bytes(auth_plain[:8], "big")
    if abs(int(time.time()) - timestamp) > 120:
        raise ValueError("VMess authentication timestamp expired")
    if binascii.crc32(auth_plain[:12]) & 0xffffffff != int.from_bytes(auth_plain[12:16], "big"):
        raise ValueError("VMess authentication checksum mismatch")
    length_key = _kdf_correct(cmd_key, b"VMess Header AEAD Key_Length", e_auth, nonce)[:16]
    length_nonce = _kdf_correct(cmd_key, b"VMess Header AEAD Nonce_Length", e_auth, nonce)[:12]
    try:
        command_len = int.from_bytes(AESGCM(length_key).decrypt(length_nonce, e_len, e_auth), "big")
    except Exception as exc:
        raise ValueError("VMess encrypted length rejected") from exc
    if command_len < 38 or command_len > 4096:
        raise ValueError("invalid VMess command length")
    end = 42 + command_len + 16
    if len(chunk) < end:
        raise ValueError("incomplete VMess command")
    e_command = chunk[42:end]
    header_key = _kdf_correct(cmd_key, b"VMess Header AEAD Key", e_auth, nonce)[:16]
    header_nonce = _kdf_correct(cmd_key, b"VMess Header AEAD Nonce", e_auth, nonce)[:12]
    try:
        command = AESGCM(header_key).decrypt(header_nonce, e_command, e_auth)
    except Exception as exc:
        raise ValueError("VMess command authentication failed") from exc
    parsed = _parse_command(command)
    return parsed["cmd"], parsed["address"], parsed["port"], chunk[end:], parsed


async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None or not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True


class _VMessStream:
    def __init__(self, meta):
        self.meta = meta
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        # scy=none is intentionally used by generated links. VMess AEAD still
        # protects the request header; stream payloads remain length-framed.
        self.buffer.extend(data)
        packets = []
        while len(self.buffer) >= 2:
            length = int.from_bytes(self.buffer[:2], "big")
            if length > 16384:
                raise ValueError("VMess data frame too large")
            if len(self.buffer) < 2 + length:
                break
            del self.buffer[:2]
            packets.append(bytes(self.buffer[:length]))
            del self.buffer[:length]
        return packets


async def relay_ws_to_tcp(ws, writer, conn_id, uid, stream):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            for payload in stream.feed(data):
                if not await check_and_use(uid, len(payload)):
                    await ws.close(code=1008, reason="quota/disabled")
                    return
                stats["total_requests"] += 1
                connections[conn_id]["bytes"] += len(payload)
                writer.write(payload)
                if writer.transport.get_write_buffer_size() > RELAY_BUF:
                    await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(ws, reader, conn_id, uid, meta):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled")
                return
            connections[conn_id]["bytes"] += len(data)
            # VMess response header: auth byte, options, command, command len.
            if first:
                response = bytes([meta["response_auth"], 0, 0, 0])
                response = _aes_cfb_encrypt(hashlib.md5(meta["key"]).digest(), hashlib.md5(meta["iv"]).digest(), response)
                payload = response + len(data).to_bytes(2, "big") + data
                first = False
            else:
                payload = len(data).to_bytes(2, "big") + data
            await ws.send_bytes(payload)
    except Exception:
        pass


async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        await ws.close(code=1008, reason="not authorized")
        return
    ip = _ws_client_ip(ws)
    if not is_ip_allowed(link, uuid, ip):
        await ws.close(code=1008, reason="ip limit reached")
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid, "ip": ip, "transport": "vmess-ws",
        "connected_at": datetime.now().isoformat(), "bytes": 0,
    }
    writer = None
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        _cmd, address, port, payload, meta = await parse_vless_header(first_chunk, uuid)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        stream = _VMessStream(meta)
        if payload:
            # Keep the same stream object so a frame split across WebSocket
            # messages is buffered correctly.
            for part in stream.feed(payload):
                writer.write(part)
            await writer.drain()
        logger.info(f"VMess WS [{conn_id}] uuid={uuid[:8]}… ip={ip} → {address}:{port}")
        done, pending = await asyncio.wait({
            asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid, stream)),
            asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid, meta)),
        }, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        asyncio.create_task(save_state())
    except (WebSocketDisconnect, asyncio.TimeoutError) as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc) or "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"VMess WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)

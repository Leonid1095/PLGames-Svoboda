"""Telemost WebRTC tunnel — proxy through Yandex Telemost DataChannel.

When TSPU switches to whitelist mode (drop-all), regular VPS/WARP proxies
become unreachable. Yandex Telemost is in the whitelist, so we tunnel
traffic through its WebRTC DataChannel.

Architecture:
  Client side (this module):
    App → SOCKS5 (localhost:PORT)
        → Multiplexer (stream mgmt, 7168-byte chunks)
        → ChaCha20-Poly1305 encryption
        → WebRTC DataChannel
        → Yandex Telemost SFU (whitelisted)
        → VPS (second "participant")
        → Internet

  Server side (deployed on VPS via srv.sh):
    Telemost SFU → DataChannel → decrypt → demux → TCP connect → Internet

Based on OlcRTC research (WTFPL license).
Adapted for Svoboda's ProxyRouter as a new proxy tier.

Usage:
    tunnel = TelemostTunnel(config)
    if await tunnel.start():
        proxy_url = tunnel.local_proxy_url  # socks5://127.0.0.1:PORT
    tunnel.stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import threading
import time
import uuid
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger("svoboda.telemost")

# ─── Constants ────────────────────────────────────────────────────────────────

TELEMOST_API = "https://cloud-api.yandex.ru/telemost_front/v2/telemost"
STUN_SERVER = "stun:stun.rtc.yandex.net:3478"

# DataChannel real limit is ~8KB; chunk at 7168 for safety
CHUNK_SIZE = 7168
BUFFER_THRESHOLD = 16384

# Default local SOCKS5 port (different from WARP:40000 and ByeDPI:1080)
DEFAULT_SOCKS_PORT = 1083

# Reconnect settings
MAX_RECONNECT_DELAY = 10
DATACHANNEL_TIMEOUT = 15
WS_PING_INTERVAL = 25
APP_PING_INTERVAL = 5

# Spoofed headers to look like legitimate Telemost client
_CLIENT_VERSION = "187.1.0"
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _uuid() -> str:
    return str(uuid.uuid4())


# ─── Crypto ───────────────────────────────────────────────────────────────────

class _Crypto:
    """ChaCha20-Poly1305 AEAD cipher for DataChannel payload.

    Each message: [12-byte random nonce][ciphertext + 16-byte auth tag]
    Overhead: 28 bytes per message.
    """

    def __init__(self, key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        self._cipher = ChaCha20Poly1305(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ct = self._cipher.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < 28:
            raise ValueError(f"Ciphertext too short: {len(blob)} bytes")
        nonce = blob[:12]
        ct = blob[12:]
        return self._cipher.decrypt(nonce, ct, None)


# ─── Multiplexer ──────────────────────────────────────────────────────────────

class _Multiplexer:
    """Stream multiplexer over a single DataChannel.

    Frame format: [Stream ID: 2B BE][Length: 2B BE][Payload: 0-7168B]
    Length=0 means close stream.
    """

    def __init__(self, send_fn):
        self._streams: dict[int, dict] = {}
        self._next_id = 1
        self._send = send_fn
        self._lock = asyncio.Lock()

    def open_stream(self) -> int:
        # Purge closed streams to prevent memory leak
        closed = [s for s, v in self._streams.items() if v["closed"]]
        for s in closed:
            del self._streams[s]

        sid = self._next_id
        # Skip IDs still in use (after wrap-around)
        attempts = 0
        while sid in self._streams and attempts < 65535:
            sid += 1
            if sid > 65535:
                sid = 1
            attempts += 1
        self._next_id = sid + 1
        if self._next_id > 65535:
            self._next_id = 1
        self._streams[sid] = {"buf": b"", "closed": False}
        return sid

    def close_stream(self, sid: int) -> None:
        if sid in self._streams:
            self._streams[sid]["closed"] = True

    async def send_data(self, sid: int, data: bytes) -> None:
        if sid not in self._streams or self._streams[sid]["closed"]:
            return
        for i in range(0, len(data), CHUNK_SIZE):
            chunk = data[i:i + CHUNK_SIZE]
            frame = struct.pack("!HH", sid, len(chunk)) + chunk
            await self._send(frame)

    async def send_close(self, sid: int) -> None:
        frame = struct.pack("!HH", sid, 0)
        await self._send(frame)
        self.close_stream(sid)

    def handle_frame(self, frame: bytes) -> None:
        if len(frame) < 4:
            return
        sid, length = struct.unpack("!HH", frame[:4])
        if length == 0:
            self.close_stream(sid)
            return
        data = frame[4:4 + length]
        if sid not in self._streams:
            self._streams[sid] = {"buf": b"", "closed": False}
        self._streams[sid]["buf"] += data

    def read_stream(self, sid: int) -> bytes:
        if sid not in self._streams:
            return b""
        buf = self._streams[sid]["buf"]
        if not buf:
            return b""
        self._streams[sid]["buf"] = b""
        return buf

    def stream_closed(self, sid: int) -> bool:
        return sid not in self._streams or self._streams[sid]["closed"]

    def reset(self) -> None:
        self._streams.clear()
        self._next_id = 1


# ─── Telemost API ─────────────────────────────────────────────────────────────

def _get_connection_info(room_url: str, display_name: str) -> dict:
    """Get WebRTC connection info from Telemost API (anonymous, no auth)."""
    import requests

    url = f"{TELEMOST_API}/conferences/{quote(room_url, safe='')}/connection"
    params = {
        "next_gen_media_platform_allowed": "true",
        "display_name": display_name,
        "waiting_room_supported": "true",
    }
    headers = {
        "User-Agent": _USER_AGENT,
        "Accept": "*/*",
        "Content-Type": "application/json",
        "Client-Instance-Id": _uuid(),
        "X-Telemost-Client-Version": _CLIENT_VERSION,
        "Idempotency-Key": _uuid(),
        "Origin": "https://telemost.yandex.ru",
        "Referer": "https://telemost.yandex.ru/",
    }
    r = requests.get(url, params=params, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()


# ─── WebRTC Peer ──────────────────────────────────────────────────────────────

class _RTCPeer:
    """WebRTC peer that connects to Telemost and exposes a DataChannel."""

    def __init__(self, room_url: str, name: str, crypto: _Crypto):
        self.room_url = room_url
        self.name = name
        self.crypto = crypto
        self.dc = None
        self.mux: Optional[_Multiplexer] = None
        self._dc_ready = asyncio.Event()
        self._ws = None
        self._ws_task = None
        self._ping_task = None
        self._connected = False

    async def connect(self) -> None:
        """Connect to Telemost, establish WebRTC DataChannel."""
        import websockets
        from aiortc import (
            RTCPeerConnection, RTCSessionDescription, RTCIceCandidate,
            RTCConfiguration, RTCIceServer,
        )

        # Run blocking HTTP request in executor to avoid blocking event loop
        loop = asyncio.get_event_loop()
        conn = await loop.run_in_executor(
            None, _get_connection_info, self.room_url, self.name,
        )
        room_id = conn["room_id"]
        peer_id = conn["peer_id"]
        credentials = conn["credentials"]
        ws_url = conn["client_configuration"]["media_server_url"]

        ice_config = RTCConfiguration(
            iceServers=[RTCIceServer(urls=[STUN_SERVER])]
        )
        self._pc_sub = RTCPeerConnection(ice_config)
        self._pc_pub = RTCPeerConnection(ice_config)
        pc_sub = self._pc_sub
        pc_pub = self._pc_pub

        # Create DataChannel on publisher connection
        self.dc = pc_pub.createDataChannel("svoboda", ordered=True)

        @self.dc.on("open")
        def _on_open():
            logger.info("DataChannel open")
            self._dc_ready.set()
            self._connected = True

        @self.dc.on("close")
        def _on_close():
            logger.warning("DataChannel closed")
            self._connected = False
            self._dc_ready.clear()

        @self.dc.on("message")
        def _on_msg(msg):
            if isinstance(msg, bytes) and self.mux:
                try:
                    plain = self.crypto.decrypt(msg)
                    self.mux.handle_frame(plain)
                except Exception as exc:
                    logger.debug("DC decrypt error: %s", exc)

        # Also handle DataChannel from subscriber side
        @pc_sub.on("datachannel")
        def _on_sub_dc(ch):
            @ch.on("message")
            def _on_sub_msg(msg):
                if isinstance(msg, bytes) and self.mux:
                    try:
                        plain = self.crypto.decrypt(msg)
                        self.mux.handle_frame(plain)
                    except Exception as exc:
                        logger.debug("SUB DC decrypt error: %s", exc)

        # Connect WebSocket for signaling
        self._ws = await websockets.connect(ws_url, ping_interval=WS_PING_INTERVAL)

        # Send hello
        hello = {
            "uid": _uuid(),
            "hello": {
                "participantMeta": {
                    "name": self.name, "role": "SPEAKER",
                    "sendAudio": False, "sendVideo": False,
                },
                "participantAttributes": {"name": self.name, "role": "SPEAKER"},
                "sendAudio": False,
                "sendVideo": False,
                "sendSharing": False,
                "participantId": peer_id,
                "roomId": room_id,
                "serviceName": "telemost",
                "credentials": credentials,
                "capabilitiesOffer": {
                    "offerAnswerMode": ["SEPARATE"],
                    "initialSubscriberOffer": ["ON_HELLO"],
                    "slotsMode": ["FROM_CONTROLLER"],
                    "simulcastMode": ["DISABLED"],
                    "selfVadStatus": ["FROM_SERVER"],
                    "dataChannelSharing": ["TO_RTP"],
                },
                "sdkInfo": {
                    "implementation": "web",
                    "version": _CLIENT_VERSION,
                    "userAgent": _USER_AGENT,
                },
                "sdkInitializationId": _uuid(),
                "disablePublisher": False,
                "disableSubscriber": False,
            },
        }
        await self._ws.send(json.dumps(hello))

        # WebSocket signaling loop
        pub_sent = False

        async def _ws_loop():
            nonlocal pub_sent
            try:
                async for raw in self._ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    uid = msg.get("uid", "")

                    # ACK server hello
                    if "serverHello" in msg:
                        await self._ws.send(json.dumps({
                            "uid": uid, "ack": {"status": {"code": "OK"}},
                        }))

                    # Subscriber SDP offer → answer, then publish
                    if "subscriberSdpOffer" in msg and not pub_sent:
                        sdp_offer = msg["subscriberSdpOffer"]
                        await pc_sub.setRemoteDescription(
                            RTCSessionDescription(sdp=sdp_offer["sdp"], type="offer")
                        )
                        ans = await pc_sub.createAnswer()
                        await pc_sub.setLocalDescription(ans)
                        await self._ws.send(json.dumps({
                            "uid": _uuid(),
                            "subscriberSdpAnswer": {
                                "pcSeq": sdp_offer["pcSeq"],
                                "sdp": pc_sub.localDescription.sdp,
                            },
                        }))
                        await self._ws.send(json.dumps({
                            "uid": uid, "ack": {"status": {"code": "OK"}},
                        }))

                        # Small delay before publisher offer
                        await asyncio.sleep(0.3)

                        offer = await pc_pub.createOffer()
                        await pc_pub.setLocalDescription(offer)
                        await self._ws.send(json.dumps({
                            "uid": _uuid(),
                            "publisherSdpOffer": {
                                "pcSeq": 1,
                                "sdp": pc_pub.localDescription.sdp,
                            },
                        }))
                        pub_sent = True

                    # Publisher SDP answer
                    if "publisherSdpAnswer" in msg:
                        await pc_pub.setRemoteDescription(
                            RTCSessionDescription(
                                sdp=msg["publisherSdpAnswer"]["sdp"], type="answer",
                            )
                        )
                        await self._ws.send(json.dumps({
                            "uid": uid, "ack": {"status": {"code": "OK"}},
                        }))

                    # ICE candidates
                    if "webrtcIceCandidate" in msg:
                        cand = msg["webrtcIceCandidate"]
                        try:
                            parts = cand["candidate"].split()
                            if len(parts) >= 8:
                                ice = RTCIceCandidate(
                                    component=int(parts[1]),
                                    foundation=parts[0].replace("candidate:", ""),
                                    ip=parts[4],
                                    port=int(parts[5]),
                                    priority=int(parts[3]),
                                    protocol=parts[2],
                                    type=parts[7],
                                    sdpMid=cand.get("sdpMid"),
                                    sdpMLineIndex=cand.get("sdpMlineIndex"),
                                )
                                target = cand.get("target", "")
                                if target == "SUBSCRIBER":
                                    await pc_sub.addIceCandidate(ice)
                                elif target == "PUBLISHER":
                                    await pc_pub.addIceCandidate(ice)
                        except Exception as ice_exc:
                            logger.debug("ICE candidate error: %s", ice_exc)

                    # Ping/pong keepalive
                    if "ping" in msg:
                        await self._ws.send(json.dumps({
                            "uid": uid, "pong": {},
                        }))

            except Exception as exc:
                logger.warning("WS signaling loop ended: %s", exc)
                self._connected = False

        # ICE candidate forwarding
        @pc_sub.on("icecandidate")
        async def _on_sub_ice(event):
            if event.candidate and self._ws:
                await self._ws.send(json.dumps({
                    "uid": _uuid(),
                    "webrtcIceCandidate": {
                        "candidate": event.candidate.candidate,
                        "sdpMid": event.candidate.sdpMid,
                        "sdpMlineIndex": event.candidate.sdpMLineIndex,
                        "target": "SUBSCRIBER", "pcSeq": 1,
                    },
                }))

        @pc_pub.on("icecandidate")
        async def _on_pub_ice(event):
            if event.candidate and self._ws:
                await self._ws.send(json.dumps({
                    "uid": _uuid(),
                    "webrtcIceCandidate": {
                        "candidate": event.candidate.candidate,
                        "sdpMid": event.candidate.sdpMid,
                        "sdpMlineIndex": event.candidate.sdpMLineIndex,
                        "target": "PUBLISHER", "pcSeq": 1,
                    },
                }))

        # Start signaling loop
        self._ws_task = asyncio.create_task(_ws_loop())

        # Setup encrypted send via mux
        async def _send_encrypted(data: bytes):
            if not self._connected or not self.dc:
                return
            enc = self.crypto.encrypt(data)
            while self.dc.bufferedAmount > BUFFER_THRESHOLD:
                await asyncio.sleep(0.001)
            self.dc.send(enc)

        self.mux = _Multiplexer(_send_encrypted)

        # Wait for DataChannel to open
        await asyncio.wait_for(self._dc_ready.wait(), timeout=DATACHANNEL_TIMEOUT)
        logger.info("Telemost tunnel connected (room=%s)", self.room_url.split("/")[-1])

    @property
    def is_connected(self) -> bool:
        return self._connected and self.dc is not None

    async def close(self) -> None:
        self._connected = False
        if self._ws_task:
            self._ws_task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
        self._ws = None
        # Close PeerConnections to release ICE agents, DTLS, UDP sockets
        for pc in (getattr(self, '_pc_pub', None), getattr(self, '_pc_sub', None)):
            if pc:
                try:
                    await pc.close()
                except Exception:
                    pass
        self._pc_pub = None
        self._pc_sub = None


# ─── SOCKS5 server (client side) ─────────────────────────────────────────────

class _SOCKS5Handler:
    """Async SOCKS5 server that tunnels connections through Telemost."""

    def __init__(self, peer: _RTCPeer, host: str, port: int):
        self._peer = peer
        self._host = host
        self._port = port
        self._server = None
        self._active_streams = 0

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sid = None
        try:
            # SOCKS5 handshake
            ver = await asyncio.wait_for(reader.readexactly(1), timeout=5)
            if ver[0] != 5:
                writer.close()
                return

            nmethods = (await reader.readexactly(1))[0]
            await reader.readexactly(nmethods)

            # No auth
            writer.write(b"\x05\x00")
            await writer.drain()

            # Connect request
            req = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            if req[1] != 1:  # Only CONNECT supported
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                await writer.drain()
                writer.close()
                return

            # Parse address
            atyp = req[3]
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:  # Domain
                length = (await reader.readexactly(1))[0]
                addr = (await reader.readexactly(length)).decode("ascii")
            elif atyp == 4:  # IPv6
                raw = await reader.readexactly(16)
                addr = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
                await writer.drain()
                writer.close()
                return

            port = struct.unpack("!H", await reader.readexactly(2))[0]

            # Check peer is alive
            if not self._peer.is_connected:
                writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)  # Host unreachable
                await writer.drain()
                writer.close()
                return

            # Open mux stream and send connect request to server
            sid = self._peer.mux.open_stream()
            self._active_streams += 1
            logger.debug("SOCKS5 connect sid=%d %s:%d", sid, addr, port)

            connect_req = json.dumps({"cmd": "connect", "addr": addr, "port": port}).encode()
            await self._peer.mux.send_data(sid, connect_req)

            # Give server time to establish connection
            await asyncio.sleep(0.3)

            # Success response
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()

            # Bidirectional relay
            async def _client_to_stream():
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data:
                            break
                        await self._peer.mux.send_data(sid, data)
                    await self._peer.mux.send_close(sid)
                except Exception:
                    pass

            async def _stream_to_client():
                try:
                    while not self._peer.mux.stream_closed(sid):
                        await asyncio.sleep(0.01)
                        data = self._peer.mux.read_stream(sid)
                        if data:
                            writer.write(data)
                            await writer.drain()
                except Exception:
                    pass

            await asyncio.gather(_client_to_stream(), _stream_to_client())

        except asyncio.TimeoutError:
            logger.debug("SOCKS5 handshake timeout")
        except Exception as exc:
            logger.debug("SOCKS5 error sid=%s: %s", sid, exc)
        finally:
            self._active_streams = max(0, self._active_streams - 1)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port,
        )
        logger.info("SOCKS5 proxy on %s:%d (Telemost tunnel)", self._host, self._port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def active_streams(self) -> int:
        return self._active_streams


# ─── Public interface (matches WarpManager / GostTunnel pattern) ──────────────

class TelemostTunnel:
    """Telemost WebRTC tunnel — SOCKS5 proxy through Yandex conference.

    Integrates into ProxyRouter as a proxy tier for whitelist scenarios.

    Usage:
        tunnel = TelemostTunnel(config)
        if tunnel.start():
            proxy_url = tunnel.local_proxy_url  # socks5://127.0.0.1:1083
        tunnel.stop()
    """

    def __init__(self, config: dict):
        self._config = config
        self._room_id: str = config.get("telemost_room_id", "")
        self._encryption_key: str = config.get("telemost_key", "")
        self._socks_port: int = config.get("telemost_socks_port", DEFAULT_SOCKS_PORT)
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._peer: Optional[_RTCPeer] = None
        self._socks: Optional[_SOCKS5Handler] = None
        self._running = False
        self._ready = threading.Event()
        self._error: Optional[str] = None

    @property
    def local_proxy_url(self) -> str:
        return f"socks5://127.0.0.1:{self._socks_port}"

    @property
    def is_running(self) -> bool:
        return self._running and self._peer is not None and self._peer.is_connected

    @property
    def is_configured(self) -> bool:
        return bool(self._room_id and self._encryption_key)

    @property
    def active_streams(self) -> int:
        return self._socks.active_streams if self._socks else 0

    def start(self, timeout: float = 20.0) -> bool:
        """Start tunnel in background thread. Returns True if SOCKS5 proxy is ready.

        Blocks up to `timeout` seconds waiting for WebRTC DataChannel.
        """
        if self._running:
            return self.is_running

        if not self.is_configured:
            logger.warning("Telemost tunnel not configured (need room_id + key)")
            return False

        self._error = None
        self._ready.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="telemost-tunnel",
        )
        self._thread.start()

        # Wait for DataChannel to open
        if self._ready.wait(timeout=timeout):
            if self._error:
                logger.error("Telemost tunnel failed: %s", self._error)
                self.stop()
                return False
            logger.info("Telemost tunnel ready: %s", self.local_proxy_url)
            return True
        else:
            logger.error("Telemost tunnel timeout (%ds)", timeout)
            self.stop()
            return False

    def stop(self) -> None:
        """Stop tunnel and clean up."""
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Telemost tunnel stopped")

    def _run_loop(self) -> None:
        """Background thread: run asyncio event loop with WebRTC + SOCKS5."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._async_main())
        except Exception as exc:
            self._error = str(exc)
            logger.error("Telemost tunnel error: %s", exc)
        finally:
            self._ready.set()  # unblock start() if still waiting
            try:
                self._loop.run_until_complete(self._async_cleanup())
            except Exception:
                pass
            self._loop.close()
            self._loop = None

    async def _async_main(self) -> None:
        """Async entry: connect to Telemost, start SOCKS5, run until stopped."""
        room_url = f"https://telemost.yandex.ru/j/{self._room_id}"
        key = bytes.fromhex(self._encryption_key)
        crypto = _Crypto(key)

        self._peer = _RTCPeer(room_url, "Svoboda-Client", crypto)

        logger.info("Connecting to Telemost room %s...", self._room_id)
        await self._peer.connect()

        # Start SOCKS5 server
        self._socks = _SOCKS5Handler(self._peer, "127.0.0.1", self._socks_port)
        await self._socks.start()

        # Signal ready
        self._ready.set()

        # Keep running until stopped
        while self._running:
            await asyncio.sleep(1)

            # Check if DataChannel is still alive
            if not self._peer.is_connected:
                logger.warning("Telemost DataChannel lost, reconnecting...")
                try:
                    self._peer.mux.reset()
                    await self._peer.close()
                    await asyncio.sleep(2)
                    self._peer = _RTCPeer(room_url, "Svoboda-Client", crypto)
                    await self._peer.connect()
                    self._socks._peer = self._peer
                    logger.info("Telemost reconnected")
                except Exception as exc:
                    logger.error("Telemost reconnect failed: %s", exc)
                    await asyncio.sleep(MAX_RECONNECT_DELAY)

    async def _async_cleanup(self) -> None:
        """Close peer and SOCKS5 server."""
        if self._socks:
            await self._socks.stop()
        if self._peer:
            await self._peer.close()

    # ─── Static helpers ───────────────────────────────────────────────────

    @staticmethod
    def check_dependencies() -> tuple[bool, str]:
        """Check if required packages are installed.

        Returns (ok, message).
        """
        missing = []
        try:
            import aiortc  # noqa: F401
        except ImportError:
            missing.append("aiortc")
        try:
            import websockets  # noqa: F401
        except ImportError:
            missing.append("websockets")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401
        except ImportError:
            missing.append("cryptography")

        if missing:
            return False, f"Missing packages: {', '.join(missing)}. Install: pip install {' '.join(missing)}"
        return True, "OK"

    @staticmethod
    def generate_key() -> str:
        """Generate random 32-byte encryption key (hex)."""
        return os.urandom(32).hex()

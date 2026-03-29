"""Pure-Python SOCKS5-over-TLS tunnel to PLGames VPS.

Replaces gost for the TLS tunnel use case. gost v3 sends custom SOCKS5
methods (128, 130) that microsocks on VPS doesn't understand → "bad version".

This tunnel speaks standard SOCKS5 RFC 1928 — no extensions, no surprises.

Chain:
  Local :1082 (SOCKS5) → TLS → proxy.svaboda-shwe.online:443 → microsocks :1080

Usage:
    tunnel = TLSTunnel(remote_host, remote_port, user, password, local_port=1082)
    tunnel.start()    # non-blocking, runs in background thread
    # socks5://127.0.0.1:1082 is now available
    tunnel.stop()
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import threading
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("svoboda.tls_tunnel")

DEFAULT_LOCAL_PORT = 1082


class TLSTunnel:
    """Local SOCKS5 proxy that forwards through TLS to remote SOCKS5 server."""

    def __init__(
        self,
        remote_host: str,
        remote_port: int,
        username: str,
        password: str,
        local_port: int = DEFAULT_LOCAL_PORT,
    ):
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._username = username
        self._password = password
        self._local_port = local_port
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @classmethod
    def from_proxy_url(cls, proxy_url: str, local_port: int = DEFAULT_LOCAL_PORT) -> "TLSTunnel":
        """Create from socks5://user:pass@host:port URL."""
        parsed = urlparse(proxy_url)
        return cls(
            remote_host=parsed.hostname or "",
            remote_port=parsed.port or 443,
            username=parsed.username or "",
            password=parsed.password or "",
            local_port=local_port,
        )

    @property
    def local_proxy_url(self) -> str:
        return f"socks5://127.0.0.1:{self._local_port}"

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    # ─── Public API ────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start local SOCKS5 listener. Non-blocking."""
        if self.is_running:
            return True

        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("127.0.0.1", self._local_port))
            self._server_sock.listen(16)
            self._server_sock.settimeout(1.0)  # for clean shutdown
            self._running = True

            self._thread = threading.Thread(
                target=self._accept_loop, daemon=True, name="tls-tunnel"
            )
            self._thread.start()

            logger.info(
                "TLS tunnel started: 127.0.0.1:%d → %s:%d",
                self._local_port, self._remote_host, self._remote_port,
            )
            return True
        except OSError as exc:
            logger.warning("TLS tunnel bind failed (port %d): %s", self._local_port, exc)
            self._running = False
            return False

    def stop(self) -> None:
        """Stop tunnel."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("TLS tunnel stopped")

    # ─── Accept loop ───────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client, addr = self._server_sock.accept()
                t = threading.Thread(
                    target=self._handle_client, args=(client,),
                    daemon=True, name=f"tunnel-{addr[1]}",
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                logger.debug("Accept error: %s", exc)

    def _handle_client(self, client: socket.socket) -> None:
        """Handle one SOCKS5 client connection."""
        remote = None
        try:
            client.settimeout(30)

            # ── Local SOCKS5 handshake (client → us) ──────────────────
            # Greeting
            data = client.recv(256)
            if len(data) < 3 or data[0] != 5:
                return
            # We accept no-auth (respond with method=0)
            client.send(b"\x05\x00")

            # Connect request
            data = client.recv(256)
            if len(data) < 7 or data[0] != 5 or data[1] != 1:
                client.send(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            # Parse target
            atyp = data[3]
            if atyp == 1:  # IPv4
                dst_addr = socket.inet_ntoa(data[4:8])
                dst_port = struct.unpack(">H", data[8:10])[0]
            elif atyp == 3:  # Domain
                dlen = data[4]
                dst_addr = data[5:5 + dlen].decode("ascii", errors="replace")
                dst_port = struct.unpack(">H", data[5 + dlen:7 + dlen])[0]
            elif atyp == 4:  # IPv6
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                dst_port = struct.unpack(">H", data[20:22])[0]
            else:
                client.send(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            # ── Connect to remote VPS via TLS + SOCKS5 ────────────────
            remote = self._connect_remote(dst_addr, dst_port)
            if remote is None:
                client.send(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            # Success
            client.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            # ── Bidirectional relay ───────────────────────────────────
            self._relay(client, remote)

        except Exception as exc:
            logger.debug("Client handler error: %s", exc)
        finally:
            try:
                client.close()
            except Exception:
                pass
            if remote:
                try:
                    remote.close()
                except Exception:
                    pass

    def _connect_remote(self, dst_addr: str, dst_port: int) -> Optional[ssl.SSLSocket]:
        """Open TLS connection to VPS, authenticate SOCKS5, request CONNECT."""
        try:
            # 1. TCP + TLS to VPS
            ctx = ssl.create_default_context()
            raw = socket.create_connection(
                (self._remote_host, self._remote_port), timeout=10
            )
            sock = ctx.wrap_socket(raw, server_hostname=self._remote_host)

            # 2. SOCKS5 greeting — standard methods only [0=no-auth, 2=user/pass]
            sock.send(b"\x05\x02\x00\x02")
            resp = sock.recv(2)
            if len(resp) < 2 or resp[0] != 5:
                logger.debug("Remote SOCKS5 bad greeting: %s", resp.hex() if resp else "empty")
                sock.close()
                return None

            # 3. Auth if required
            if resp[1] == 2:
                user = self._username.encode("utf-8")
                pwd = self._password.encode("utf-8")
                auth = b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd
                sock.send(auth)
                auth_resp = sock.recv(2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    logger.debug("Remote SOCKS5 auth failed")
                    sock.close()
                    return None
            elif resp[1] == 0:
                pass  # No auth needed
            else:
                logger.debug("Remote SOCKS5 unsupported method: %d", resp[1])
                sock.close()
                return None

            # 4. CONNECT request
            if self._is_ip(dst_addr):
                # IPv4
                req = b"\x05\x01\x00\x01" + socket.inet_aton(dst_addr) + struct.pack(">H", dst_port)
            else:
                # Domain
                addr_bytes = dst_addr.encode("ascii")
                req = b"\x05\x01\x00\x03" + bytes([len(addr_bytes)]) + addr_bytes + struct.pack(">H", dst_port)
            sock.send(req)

            resp = sock.recv(32)
            if len(resp) < 4 or resp[1] != 0:
                status = resp[1] if len(resp) >= 2 else -1
                logger.debug("Remote SOCKS5 CONNECT failed: status=%d for %s:%d", status, dst_addr, dst_port)
                sock.close()
                return None

            return sock

        except Exception as exc:
            logger.debug("Remote connect failed: %s", exc)
            return None

    @staticmethod
    def _is_ip(addr: str) -> bool:
        try:
            socket.inet_aton(addr)
            return True
        except Exception:
            return False

    @staticmethod
    def _relay(sock1: socket.socket, sock2: socket.socket) -> None:
        """Bidirectional relay between two sockets."""
        import select
        try:
            while True:
                readable, _, _ = select.select([sock1, sock2], [], [], 60)
                if not readable:
                    break
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    if s is sock1:
                        sock2.sendall(data)
                    else:
                        sock1.sendall(data)
        except Exception:
            pass

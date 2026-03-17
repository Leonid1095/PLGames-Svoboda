"""ByeDPI-style SOCKS5 proxy — DPI bypass without admin rights.

Fallback when WinDivert/admin is not available.
Runs as a local SOCKS5 proxy on localhost:1080.
Applications connect through it, proxy applies split/disorder
to TLS ClientHello in user-space.

Supports: split, disorder (reorder segments)
Does NOT support: fake (needs raw sockets), TTL manipulation

Usage:
    proxy = DesyncSocksProxy(config, hostlist)
    proxy.start()  # non-blocking, runs in thread
    # Configure system/app to use SOCKS5 localhost:1080
    proxy.stop()
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.socks")

# Default split positions for TLS ClientHello
DEFAULT_SPLIT_POS = [3, 100]  # split after 3 bytes and after 100 bytes


class DesyncSocksProxy:
    """SOCKS5 proxy with DPI desync in user-space.

    Split/disorder TLS ClientHello without admin rights.
    """

    def __init__(
        self,
        config: dict,
        hostlist: Optional[set[str]] = None,
        port: int = 1080,
        split_positions: Optional[list[int]] = None,
    ):
        self.port = config.get("socks_port", port)
        self.hostlist = hostlist or set()
        self.split_positions = split_positions or DEFAULT_SPLIT_POS
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._connections = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def connection_count(self) -> int:
        return self._connections

    def start(self) -> None:
        """Start proxy in background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="socks-proxy")
        self._thread.start()
        logger.info("SOCKS5 proxy started on localhost:%d", self.port)

    def stop(self) -> None:
        """Stop proxy."""
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("SOCKS5 proxy stopped")

    def load_hostlist(self, path: Path) -> None:
        """Load hostlist from file."""
        if path.exists():
            domains = path.read_text(encoding="utf-8", errors="replace").strip().split("\n")
            self.hostlist = {d.strip().lower() for d in domains if d.strip() and not d.startswith("#")}
            logger.info("SOCKS proxy loaded %d domains", len(self.hostlist))

    # ─── Internal ─────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Run asyncio event loop in thread."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as exc:
            logger.error("SOCKS proxy error: %s", exc)
        finally:
            self._loop.close()

    async def _serve(self) -> None:
        """Main server coroutine."""
        server = await asyncio.start_server(
            self._handle_client, "127.0.0.1", self.port,
        )
        async with server:
            while self._running:
                await asyncio.sleep(0.5)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle one SOCKS5 connection."""
        try:
            # SOCKS5 handshake
            header = await asyncio.wait_for(reader.read(2), timeout=10)
            if len(header) < 2 or header[0] != 0x05:
                writer.close()
                return

            nmethods = header[1]
            await reader.read(nmethods)

            # No auth
            writer.write(b"\x05\x00")
            await writer.drain()

            # SOCKS5 request
            req = await asyncio.wait_for(reader.read(4), timeout=10)
            if len(req) < 4 or req[1] != 0x01:  # CONNECT only
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                writer.close()
                return

            # Parse destination
            atyp = req[3]
            if atyp == 0x01:  # IPv4
                addr_bytes = await reader.read(4)
                dst_host = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:  # Domain
                domain_len = (await reader.read(1))[0]
                dst_host = (await reader.read(domain_len)).decode()
            elif atyp == 0x04:  # IPv6
                addr_bytes = await reader.read(16)
                dst_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                writer.close()
                return

            port_bytes = await reader.read(2)
            dst_port = struct.unpack("!H", port_bytes)[0]

            # Connect to destination
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(dst_host, dst_port), timeout=10,
                )
            except Exception:
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                writer.close()
                return

            # Success
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            self._connections += 1

            # Check if this domain needs desync
            needs_desync = self._should_desync(dst_host, dst_port)

            # Relay data
            await self._relay(reader, writer, remote_reader, remote_writer, needs_desync)

        except Exception as exc:
            logger.debug("SOCKS connection error: %s", exc)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _should_desync(self, host: str, port: int) -> bool:
        """Check if this connection needs DPI bypass."""
        if port != 443:
            return False
        if not self.hostlist:
            return True  # no hostlist = desync all HTTPS

        host_lower = host.lower()
        # Check exact match and parent domain
        parts = host_lower.split(".")
        for i in range(len(parts)):
            domain = ".".join(parts[i:])
            if domain in self.hostlist:
                return True
        return False

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        needs_desync: bool,
    ) -> None:
        """Relay data between client and remote, applying desync to first TLS packet."""
        first_packet = True

        async def client_to_remote():
            nonlocal first_packet
            try:
                while True:
                    data = await asyncio.wait_for(client_reader.read(65536), timeout=300)
                    if not data:
                        break

                    if first_packet and needs_desync and len(data) > 10:
                        first_packet = False
                        # Check if TLS ClientHello (starts with 0x16 0x03)
                        if data[0] == 0x16 and data[1] == 0x03:
                            await self._send_split(remote_writer, data)
                            continue

                    remote_writer.write(data)
                    await remote_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    remote_writer.close()
                except Exception:
                    pass

        async def remote_to_client():
            try:
                while True:
                    data = await asyncio.wait_for(remote_reader.read(65536), timeout=300)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    client_writer.close()
                except Exception:
                    pass

        await asyncio.gather(client_to_remote(), remote_to_client())

    async def _send_split(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        """Split TLS ClientHello into segments (user-space desync).

        Splits at configured positions, sends each part separately.
        DPI sees incomplete ClientHello in first packet → can't read SNI.
        """
        positions = sorted(p for p in self.split_positions if p < len(data))

        if not positions:
            writer.write(data)
            await writer.drain()
            return

        # Split and send each part
        prev = 0
        for pos in positions:
            chunk = data[prev:pos]
            if chunk:
                writer.write(chunk)
                await writer.drain()
                await asyncio.sleep(0.01)  # tiny delay between segments
            prev = pos

        # Send remainder
        if prev < len(data):
            writer.write(data[prev:])
            await writer.drain()

        logger.debug("Split TLS ClientHello: %d bytes → %d segments", len(data), len(positions) + 1)

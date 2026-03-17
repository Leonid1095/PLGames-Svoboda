"""ISPProfiler — ISP detection and network profile analysis."""

from __future__ import annotations

import json
import logging
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("svoboda.profiler")

# ─── Known network middlebox signatures ────────────────────────────────────────

MIDDLEBOX_SIGNATURES: dict[str, dict] = {
    "ektako_yadro_v2": {
        "description": "Ektako/Yadro middlebox v2",
        "ttl_range": (53, 58),
        "window_size": 0,
        "effective_methods": ["disorder2", "fake"],
    },
    "signaltek_v1": {
        "description": "Signaltek middlebox v1",
        "ttl_range": (64, 64),
        "window_size": 0,
        "effective_methods": ["multisplit", "overlap"],
    },
    "transit_block": {
        "description": "Transit middlebox (upstream)",
        "ttl_range": (47, 52),
        "window_size": None,  # любой
        "effective_methods": ["fake", "disorder"],
    },
}

# Предустановленные seed-стратегии по ISP
ISP_SEED_STRATEGIES: dict[str, list[list[str]]] = {
    "rostelecom": [
        ["fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5", "multidisorder:pos=3"],
        ["fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_seq=-10000", "multidisorder:pos=midsld"],
    ],
    "mts": [
        ["fake:blob=fake_default_tls:ip_ttl=8:ip6_ttl=8:tcp_md5", "multisplit:pos=midsld"],
        ["fake:blob=fake_default_tls:ip_ttl=7:ip6_ttl=7:tcp_md5:tls_mod=rnd,rndsni", "multisplit:pos=midsld"],
    ],
    "megafon": [
        ["fake:blob=fake_default_tls:ip_ttl=6:ip6_ttl=6:tcp_md5", "send:ipfrag", "drop"],
        ["fake:blob=fake_default_tls:ip_ttl=6:ip6_ttl=6", "fakedsplit:pos=2"],
    ],
    "tele2": [
        ["fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_ack=-66000", "multidisorder:pos=midsld"],
        ["fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_seq=-10000", "multidisorder:pos=midsld"],
    ],
    "beeline": [
        ["fake:blob=fake_default_tls:ip_ttl=6:ip6_ttl=6:tcp_seq=-10000:tcp_md5"],
    ],
    "tattelecom": [
        ["fakedsplit:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4", "multidisorder:pos=2"],
    ],
    "er-telecom": [
        # Proven on AS42116: stateful DPI, fake=0.000, multidisorder+seqovl works
        ["multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000"],
        ["multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000", "multidisorder:pos=1,midsld"],
    ],
    "ttk": [
        ["fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5", "multisplit:pos=midsld"],
    ],
}

# Маппинг ASN → имя провайдера
ASN_TO_ISP: dict[str, str] = {
    "AS12389": "rostelecom",
    "AS25513": "rostelecom",
    "AS8402": "rostelecom",
    "AS8580": "rostelecom",
    "AS8369": "rostelecom",
    "AS8427": "rostelecom",
    "AS8334": "mts",
    "AS25159": "mts",
    "AS57681": "mts",
    "AS31133": "megafon",
    "AS25086": "megafon",
    "AS44507": "megafon",
    "AS15493": "tele2",
    "AS12958": "tele2",
    "AS3216": "beeline",
    "AS8790": "beeline",
    "AS41330": "beeline",
    "AS15974": "tattelecom",
    # ER-Telecom (Dom.ru)
    "AS42116": "er-telecom",
    "AS34533": "er-telecom",
    "AS29497": "er-telecom",
    # TTK
    "AS20485": "ttk",
    "AS15835": "ttk",
    # NetByNet
    "AS12714": "netbynet",
}


class ISPProfile:
    """ISP and network middlebox profile."""

    def __init__(
        self,
        external_ip: str = "",
        asn: str = "",
        isp_name: str = "unknown",
        org: str = "",
        region: str = "",
        middlebox_type: str = "unknown",
        middlebox_ttl: Optional[int] = None,
        middlebox_window: Optional[int] = None,
        last_check: Optional[str] = None,
    ):
        self.external_ip = external_ip
        self.asn = asn
        self.isp_name = isp_name
        self.org = org
        self.region = region
        self.middlebox_type = middlebox_type
        self.middlebox_ttl = middlebox_ttl
        self.middlebox_window = middlebox_window
        self.last_check = last_check or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        """Сериализация."""
        return {
            "external_ip": self.external_ip,
            "asn": self.asn,
            "isp_name": self.isp_name,
            "org": self.org,
            "region": self.region,
            "middlebox_type": self.middlebox_type,
            "middlebox_ttl": self.middlebox_ttl,
            "middlebox_window": self.middlebox_window,
            "last_check": self.last_check,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ISPProfile:
        """Десериализация."""
        return cls(**{k: v for k, v in data.items() if k in cls.__init__.__code__.co_varnames})


class ISPProfiler:
    """ISP detection and network middlebox profiling."""

    def __init__(self, config: dict):
        self._base_dir = Path(config.get("_base_dir", "."))
        self._profile_path = self._base_dir / config.get("isp_profile_path", "isp_profile.json")
        self._check_interval_hours = config.get("isp_check_interval_hours", 24)
        self.profile: Optional[ISPProfile] = None
        self._load_profile()

    def detect(self, force: bool = False) -> ISPProfile:
        """Full ISP and network profile detection cycle."""
        if not force and self.profile and not self._is_stale():
            logger.info("Using cached ISP profile: %s", self.profile.isp_name)
            return self.profile

        logger.info("Starting ISP detection...")

        profile = ISPProfile()

        # 1. Определить внешний IP
        profile.external_ip = self._get_external_ip()

        # 2. Определить ASN и провайдера
        if profile.external_ip:
            asn_info = self._get_asn_info(profile.external_ip)
            profile.asn = asn_info.get("asn", "")
            profile.org = asn_info.get("org", "")
            profile.region = asn_info.get("region", "")
            profile.isp_name = self._resolve_isp_name(profile.asn, profile.org)

        # 3. Detect middlebox signature via RST analysis
        mb_info = self._detect_middlebox_signature()
        profile.middlebox_type = mb_info.get("type", "unknown")
        profile.middlebox_ttl = mb_info.get("ttl")
        profile.middlebox_window = mb_info.get("window")

        profile.last_check = datetime.now(timezone.utc).isoformat()
        self.profile = profile
        self._save_profile()

        logger.info(
            "ISP detected: %s (ASN: %s, middlebox: %s)",
            profile.isp_name, profile.asn, profile.middlebox_type,
        )
        return profile

    def get_seed_strategies(self) -> list[list[str]]:
        """Получить seed-стратегии для текущего ISP."""
        if not self.profile:
            return []
        return ISP_SEED_STRATEGIES.get(self.profile.isp_name, [])

    # ─── Внешний IP ────────────────────────────────────────────────────────

    def _get_external_ip(self) -> str:
        """Определить внешний IP через публичные API."""
        apis = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "https://api.my-ip.io/v2/ip.txt",
        ]
        for api in apis:
            try:
                resp = requests.get(api, timeout=5)
                if resp.status_code == 200:
                    if api.endswith("json"):
                        return resp.json().get("ip", "")
                    return resp.text.strip()
            except Exception:
                continue

        logger.warning("Failed to determine external IP")
        return ""

    # ─── ASN info ──────────────────────────────────────────────────────────

    def _get_asn_info(self, ip: str) -> dict:
        """Определить ASN и организацию через ipinfo.io."""
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                org = data.get("org", "")
                asn = org.split(" ")[0] if org else ""
                return {
                    "asn": asn,
                    "org": org,
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                }
        except Exception as exc:
            logger.warning("Failed to get ASN info: %s", exc)

        return {}

    def _resolve_isp_name(self, asn: str, org: str) -> str:
        """Определить имя ISP по ASN или названию организации."""
        # Точное совпадение по ASN
        if asn in ASN_TO_ISP:
            return ASN_TO_ISP[asn]

        # Поиск по ключевым словам в org
        org_lower = org.lower()
        keywords = {
            "rostelecom": "rostelecom",
            "ростелеком": "rostelecom",
            "mts": "mts",
            "мтс": "mts",
            "megafon": "megafon",
            "мегафон": "megafon",
            "tele2": "tele2",
            "теле2": "tele2",
            "beeline": "beeline",
            "билайн": "beeline",
            "vimpelcom": "beeline",
            "tattelecom": "tattelecom",
            "таттелеком": "tattelecom",
        }
        for keyword, isp_name in keywords.items():
            if keyword in org_lower:
                return isp_name

        logger.info("Unknown ISP: ASN=%s org=%s", asn, org)
        return "unknown"

    # ─── ТСПУ signature detection ──────────────────────────────────────────

    def _detect_middlebox_signature(self) -> dict:
        """Определить тип ТСПУ по RST-пакетам."""
        try:
            return self._detect_via_raw_socket()
        except Exception as exc:
            logger.warning("Raw socket TSPU detection failed: %s", exc)

        try:
            return self._detect_via_scapy()
        except ImportError:
            logger.info("scapy not available, skipping RST analysis")
        except Exception as exc:
            logger.warning("Scapy TSPU detection failed: %s", exc)

        return {"type": "unknown"}

    def _detect_via_raw_socket(self) -> dict:
        """Определить ТСПУ через raw socket (TCP SYN → анализ RST)."""
        target_host = "youtube.com"
        target_port = 443

        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            return {"type": "unknown"}

        # Пытаемся подключиться и поймать RST
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_ip, target_port))

            if result == 0:
                # Соединение установлено — нет блокировки на уровне TCP
                # Попробуем отправить TLS ClientHello с YouTube SNI
                rst_info = self._send_tls_hello_and_check_rst(sock, target_host)
                sock.close()
                if rst_info:
                    return rst_info
            else:
                sock.close()
                return {"type": "unknown", "note": "connection_refused"}

        except socket.timeout:
            return {"type": "unknown", "note": "timeout"}
        except Exception as exc:
            logger.debug("Raw socket detection error: %s", exc)

        return {"type": "unknown"}

    def _send_tls_hello_and_check_rst(self, sock: socket.socket, hostname: str) -> Optional[dict]:
        """Отправить TLS ClientHello и проверить RST-ответ."""
        # Минимальный TLS ClientHello с SNI
        sni = hostname.encode("ascii")
        sni_ext = (
            b"\x00\x00"  # SNI extension type
            + struct.pack("!H", len(sni) + 5)  # ext length
            + struct.pack("!H", len(sni) + 3)  # SNI list length
            + b"\x00"  # host_name type
            + struct.pack("!H", len(sni))  # name length
            + sni
        )

        extensions = sni_ext
        client_hello = (
            b"\x01"  # HandshakeType: ClientHello
            + b"\x00\x00\x00"  # placeholder length (fill below)
            + b"\x03\x03"  # TLS 1.2
            + b"\x00" * 32  # random
            + b"\x00"  # session_id length = 0
            + b"\x00\x02\x13\x01"  # cipher_suites: TLS_AES_128_GCM_SHA256
            + b"\x01\x00"  # compression_methods: null
            + struct.pack("!H", len(extensions))
            + extensions
        )

        # Fix handshake length
        hs_len = len(client_hello) - 4
        client_hello = (
            client_hello[0:1]
            + struct.pack("!I", hs_len)[1:]  # 3 bytes
            + client_hello[4:]
        )

        # TLS record
        record = (
            b"\x16\x03\x01"  # ContentType: Handshake, TLS 1.0
            + struct.pack("!H", len(client_hello))
            + client_hello
        )

        try:
            sock.sendall(record)
            # Ждём ответ (может быть RST или ServerHello)
            time.sleep(0.5)
            response = sock.recv(4096)

            if not response:
                return {"type": "unknown", "note": "connection_closed"}

            # Если получили TLS record — не заблокирован
            if response[0:1] == b"\x16":
                return None  # ServerHello — нет блокировки

        except ConnectionResetError:
            # RST получен — это блокировка ТСПУ
            return {"type": "rst_injection", "note": "connection_reset_after_sni"}
        except socket.timeout:
            return {"type": "possible_blackhole", "note": "timeout_after_sni"}
        except Exception:
            pass

        return None

    def _detect_via_scapy(self) -> dict:
        """Определить ТСПУ через scapy (более точный RST-анализ)."""
        from scapy.all import IP, TCP, sr1, conf

        conf.verb = 0
        target_host = "youtube.com"

        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            return {"type": "unknown"}

        # Отправить SYN
        syn = IP(dst=target_ip) / TCP(dport=443, flags="S", sport=40000 + int(time.time()) % 10000)
        response = sr1(syn, timeout=5)

        if response is None:
            return {"type": "unknown", "note": "no_response_to_syn"}

        if response.haslayer(TCP):
            tcp = response[TCP]

            # SYN-ACK — нормальный ответ, не на уровне TCP блокировка
            if tcp.flags == "SA":
                return {"type": "unknown", "note": "syn_ack_received"}

            # RST — анализируем сигнатуру
            if "R" in str(tcp.flags):
                ttl = response[IP].ttl
                window = tcp.window

                result = {
                    "ttl": ttl,
                    "window": window,
                    "type": "unknown_rst",
                }

                # Сопоставляем с известными сигнатурами
                for sig_name, sig in MIDDLEBOX_SIGNATURES.items():
                    ttl_lo, ttl_hi = sig["ttl_range"]
                    if ttl_lo <= ttl <= ttl_hi:
                        if sig["window_size"] is None or window == sig["window_size"]:
                            result["type"] = sig_name
                            result["description"] = sig["description"]
                            break

                return result

        return {"type": "unknown"}

    # ─── Persistence ───────────────────────────────────────────────────────

    def _load_profile(self) -> None:
        """Загрузить профиль с диска."""
        if not self._profile_path.exists():
            return
        try:
            data = json.loads(self._profile_path.read_text(encoding="utf-8"))
            self.profile = ISPProfile.from_dict(data)
            logger.info("Loaded ISP profile: %s", self.profile.isp_name)
        except Exception as exc:
            logger.warning("Failed to load ISP profile: %s", exc)

    def _save_profile(self) -> None:
        """Сохранить профиль на диск."""
        if not self.profile:
            return
        self._profile_path.parent.mkdir(parents=True, exist_ok=True)
        self._profile_path.write_text(
            json.dumps(self.profile.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("Saved ISP profile to %s", self._profile_path)

    def _is_stale(self) -> bool:
        """Проверить, устарел ли профиль."""
        if not self.profile or not self.profile.last_check:
            return True
        try:
            last = datetime.fromisoformat(self.profile.last_check)
            age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
            return age_hours >= self._check_interval_hours
        except Exception:
            return True

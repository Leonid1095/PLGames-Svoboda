"""Traffic Morpher — make DPI bypass traffic look like real browser traffic.

ML-based DPI (RKN 2026) detects bypass by analyzing:
- Packet size distribution (92% accuracy)
- TCP window scaling (browser fingerprint)
- TLS fingerprint (JA3/JA4)

Morpher creates browser profiles that zapret2 applies to packets,
making them statistically indistinguishable from real Chrome/Firefox.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("svoboda.morpher")


@dataclass
class BrowserProfile:
    """Browser fingerprint profile for traffic morphing."""
    name: str
    # TCP
    wsize: int = 65535       # TCP window size
    wscale: int = 7          # TCP window scale factor
    # TLS
    tls_mod: str = "rnd,rndsni"  # TLS modification flags
    use_padencap: bool = True    # TLS padding extension
    # Fake packet
    fake_repeats: int = 6       # how many fake packets
    # Description
    desc: str = ""

    def to_wssize_call(self) -> str:
        """Generate wssize lua-desync call."""
        return f"wssize:wsize={self.wsize}:scale={self.wscale}"

    def to_tls_mod(self) -> str:
        """Generate tls_mod parameter string."""
        mods = self.tls_mod
        if self.use_padencap:
            mods += ",padencap" if mods else "padencap"
        return mods

    def apply_to_fake(self, fake_call: str) -> str:
        """Add morphing params to an existing fake call."""
        parts = fake_call.split(":")
        # Add tls_mod if not present
        has_tls_mod = any(p.startswith("tls_mod=") for p in parts)
        if not has_tls_mod and self.tls_mod:
            parts.append(f"tls_mod={self.to_tls_mod()}")
        return ":".join(parts)


# ─── Known browser profiles ──────────────────────────────────────────────────

PROFILES = {
    "chrome_win": BrowserProfile(
        name="chrome_win",
        wsize=65535,
        wscale=7,
        tls_mod="rnd,rndsni,dupsid",
        use_padencap=True,
        fake_repeats=6,
        desc="Chrome 120+ on Windows (most common)",
    ),
    "chrome_android": BrowserProfile(
        name="chrome_android",
        wsize=65535,
        wscale=7,
        tls_mod="rnd,rndsni",
        use_padencap=True,
        fake_repeats=4,
        desc="Chrome on Android",
    ),
    "firefox_win": BrowserProfile(
        name="firefox_win",
        wsize=32768,
        wscale=6,
        tls_mod="rnd,rndsni",
        use_padencap=True,
        fake_repeats=6,
        desc="Firefox 121+ on Windows",
    ),
    "firefox_linux": BrowserProfile(
        name="firefox_linux",
        wsize=32768,
        wscale=6,
        tls_mod="rnd,rndsni",
        use_padencap=False,
        fake_repeats=6,
        desc="Firefox on Linux",
    ),
    "safari_mac": BrowserProfile(
        name="safari_mac",
        wsize=65535,
        wscale=8,
        tls_mod="rnd",
        use_padencap=False,
        fake_repeats=4,
        desc="Safari 17+ on macOS",
    ),
    "edge_win": BrowserProfile(
        name="edge_win",
        wsize=65535,
        wscale=7,
        tls_mod="rnd,rndsni,dupsid",
        use_padencap=True,
        fake_repeats=6,
        desc="Edge on Windows (Chromium-based)",
    ),
}

# Default profile
DEFAULT_PROFILE = "chrome_win"


class TrafficMorpher:
    """Applies browser profile to zapret2 strategies.

    Usage:
        morpher = TrafficMorpher(profile="chrome_win")
        extra_calls = morpher.get_permanent_calls()
        # Add to winws2 command
    """

    def __init__(self, profile_name: str = DEFAULT_PROFILE, enabled: bool = True):
        self.enabled = enabled
        self.profile = PROFILES.get(profile_name, PROFILES[DEFAULT_PROFILE])
        logger.info("Traffic morpher: profile=%s enabled=%s", self.profile.name, enabled)

    def get_permanent_calls(self) -> list[str]:
        """Get additional lua-desync calls for permanent winws2.

        These are prepended BEFORE the user strategy to set up
        browser-like TCP/TLS parameters.
        """
        if not self.enabled:
            return []

        calls = []

        # 1. Window size morphing (must be first — affects SYN)
        calls.append(self.profile.to_wssize_call())

        return calls

    def morph_strategy(self, flags: list[str]) -> list[str]:
        """Add morphing parameters to an existing strategy.

        Modifies fake calls to include tls_mod and padding.
        """
        if not self.enabled:
            return flags

        morphed = []
        for call in flags:
            func = call.split(":")[0]

            if func in ("fake", "fakedsplit"):
                # Add tls_mod + padencap to fake calls
                morphed.append(self.profile.apply_to_fake(call))
            else:
                morphed.append(call)

        return morphed

    def get_tls_init(self) -> Optional[str]:
        """Get TLS initialization lua-init code.

        Applies tls_mod to fake_default_tls blob globally.
        """
        if not self.enabled or not self.profile.tls_mod:
            return None

        mods = self.profile.to_tls_mod()
        return f'fake_default_tls = tls_mod(fake_default_tls,"{mods}")'

    @staticmethod
    def get_random_profile() -> str:
        """Pick a random browser profile (for diversity)."""
        return random.choice(list(PROFILES.keys()))

    @staticmethod
    def get_profile_names() -> list[str]:
        """List available profiles."""
        return list(PROFILES.keys())

    # ── Round-robin rotation for warm-pool failover ─────────────────────
    # TSPU now does statistical analysis on JA3/JA4. A single profile used
    # over many connections becomes a fingerprint TSPU can blocklist. Each
    # failover (next_alternative in HostSolver) advances this index so the
    # subsequent winws2 restart uses a different browser fingerprint with
    # the swapped strategy. Never go back to a profile recently used.
    _rotation_idx: int = 0

    @classmethod
    def next_profile_name(cls, exclude: Optional[str] = None) -> str:
        """Advance the rotation index and return the next profile name.

        Args:
            exclude: profile name to skip (typically the currently active
                one, so we always rotate to *some other* profile).

        Returns:
            Next profile name in deterministic round-robin order.
        """
        names = list(PROFILES.keys())
        for _ in range(len(names)):
            cls._rotation_idx = (cls._rotation_idx + 1) % len(names)
            candidate = names[cls._rotation_idx]
            if candidate != exclude:
                return candidate
        # All profiles equal exclude (only one profile? impossible with PROFILES dict)
        return names[0]

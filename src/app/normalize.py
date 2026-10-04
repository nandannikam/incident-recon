"""
Phase 3, Step 4 — value normalisation for cross-host correlation.

The same machine, address or file shows up spelled differently in different
logs: ``SCRANTON.dmevals.local`` / ``scranton`` / ``Scranton.``, ``::ffff:10.0.0.1``
/ ``10.0.0.1`` / ``010.000.000.001``, ``SHA256=ABC...`` / ``abc...``. Matching
raw strings would miss those links, so this module computes a canonical form of
each and stores it in ``Event.metadata`` under underscore-prefixed keys:

    _host_norm   canonical host name of ``Event.source``
    _ip_norm     canonical IP address of the event's destination/source IP
    _hashes      {"sha256": "...", "md5": "...", ...} parsed from a Sysmon
                 ``Hashes`` field (only present when the event has one)

Nothing existing is modified: ``source``, ``actor``, ``target`` and every other
metadata key stay exactly as parsed, so provenance and rule behaviour do not
change. Consumers (cross-host correlation) opt in by reading the ``_`` keys.
Normalisation is idempotent and never raises on odd input -- a value that
cannot be normalised simply yields no key.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

from app.models import Event, EventType

# Hash algorithms Sysmon reports, with the hex length each must have.
_HASH_LENGTHS: dict[str, int] = {"md5": 32, "sha1": 40, "sha256": 64, "imphash": 32}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_IPV4_LOOSE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Placeholder values logs use for "nothing here".
_EMPTY_MARKERS = {"", "-", "n/a", "none", "null", "unknown"}


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in _EMPTY_MARKERS else text


def normalize_ip(value: Any) -> str | None:
    """Canonical text form of an IPv4/IPv6 address, or None if it is not one.

    Handles surrounding brackets, zero-padded IPv4 octets, IPv4-mapped IPv6
    (``::ffff:1.2.3.4`` -> ``1.2.3.4``) and un-compressed IPv6.
    """
    text = _clean(value)
    if text is None:
        return None
    text = text.strip("[]").strip()

    if _IPV4_LOOSE.match(text):
        octets = [int(part) for part in text.split(".")]
        if any(octet > 255 for octet in octets):
            return None
        return ".".join(str(octet) for octet in octets)

    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_host(value: Any) -> str | None:
    """Canonical host name: lower case, no trailing dot, and only the first DNS
    label (``SCRANTON.dmevals.local`` -> ``scranton``). IP addresses are
    returned in their canonical IP form instead. Placeholders give None.

    Limitation: two hosts with the same short name in different domains are
    treated as one machine.
    """
    text = _clean(value)
    if text is None:
        return None
    ip = normalize_ip(text)
    if ip is not None:
        return ip
    first_label = text.rstrip(".").split(".", 1)[0].strip().lower()
    return first_label or None


def extract_hashes(value: Any) -> dict[str, str]:
    """Parse a Sysmon hash string (``SHA1=..,MD5=..,SHA256=..,IMPHASH=..``).

    Returns ``{"sha1": "...", ...}`` with lower-case hex. Entries with an
    unknown algorithm, non-hex characters or the wrong length are dropped, so
    a truncated or corrupt hash can never produce a false match.
    """
    text = _clean(value)
    if text is None:
        return {}
    found: dict[str, str] = {}
    for part in text.split(","):
        algorithm, separator, digest = part.partition("=")
        if not separator:
            continue
        algorithm = algorithm.strip().lower()
        digest = digest.strip()
        expected = _HASH_LENGTHS.get(algorithm)
        if expected and len(digest) == expected and _HEX.match(digest):
            found[algorithm] = digest.lower()
    return found


def _first_ip(event: Event) -> str | None:
    candidates: list[Any] = [
        event.metadata.get("DestinationIp"),
        event.metadata.get("SourceIp"),
    ]
    if event.event_type == EventType.NETWORK_CONNECTION:
        candidates.append(event.target)
    for candidate in candidates:
        ip = normalize_ip(candidate)
        if ip is not None:
            return ip
    return None


def normalize_event(event: Event) -> Event:
    """Add the normalised keys to ``event.metadata`` (in place) and return it."""
    host = normalize_host(event.source)
    if host is not None:
        event.metadata["_host_norm"] = host

    ip = _first_ip(event)
    if ip is not None:
        event.metadata["_ip_norm"] = ip

    hashes: dict[str, str] = {}
    for key in ("Hashes", "Hash"):
        hashes.update(extract_hashes(event.metadata.get(key)))
    if hashes:
        event.metadata["_hashes"] = hashes
    return event


def normalize_events(events: Iterable[Event]) -> list[Event]:
    """Normalise every event in place; returns them as a list."""
    return [normalize_event(event) for event in events]

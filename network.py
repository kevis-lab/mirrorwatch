"""Network helpers with a small SSRF safety boundary."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def hostname_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")


def get_host_and_ips(url: str) -> tuple[str, list[str]]:
    host = hostname_from_url(url)
    if not host:
        return "", []
    try:
        records = socket.getaddrinfo(host, None)
        addresses = sorted({record[4][0] for record in records})
        return host, addresses
    except OSError:
        return host, []


def is_public_target(url: str) -> tuple[bool, str, list[str]]:
    """Return false for loopback/private/link-local targets before requesting them."""
    host, ips = get_host_and_ips(url)
    if not host or not ips:
        return False, host, ips
    try:
        safe = all(ipaddress.ip_address(ip).is_global for ip in ips)
    except ValueError:
        safe = False
    return safe, host, ips

"""Security utilities for URL validation and SSRF prevention."""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger("backend.security")

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def validate_webhook_url(url: str) -> None:
    """Validate that a webhook URL does not target private/internal networks.

    Raises ValueError if the URL is unsafe.
    """
    if not url:
        raise ValueError("URL is empty")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Only http/https allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("No hostname in URL")

    # Resolve hostname and check all resolved IPs
    try:
        resolved = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from e

    for _, _, _, _, sockaddr in resolved:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            raise ValueError("Webhook URL resolves to a blocked network range")
        for blocked in _BLOCKED_NETWORKS:
            if ip in blocked:
                raise ValueError("Webhook URL resolves to a blocked network range")

    logger.debug("Webhook URL validated: %s", parsed.hostname)

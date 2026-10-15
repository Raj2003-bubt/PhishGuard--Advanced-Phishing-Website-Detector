"""URL safety checks for the optional, networked phishing analysis stage.

These checks lower the risk of accidental localhost/private-network requests, but
cannot fully prevent DNS rebinding (resolution and the HTTP connection are separate).
Only scan websites you have permission to contact.
"""

import ipaddress
import socket
from urllib.parse import urlsplit


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value.lower().startswith(("http://", "https://")) and "://" not in value:
        value = "https://" + value
    return value


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        _ = parsed.port  # Catch malformed port numbers.
        return (parsed.scheme.lower() in {"http", "https"}
                and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None)
    except (ValueError, TypeError):
        return False


def ensure_public_target(url: str) -> None:
    """Reject malformed, local, and non-public targets before a network request.

    Note: DNS can change after validation; this is defense in depth, not a
    guarantee against DNS rebinding. Never run this as a multi-user web service.
    """
    if not is_valid_url(url):
        raise ValueError("Only HTTP(S) URLs without embedded credentials are supported.")
    parsed = urlsplit(url)
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local network targets are not supported.")
    try:
        addresses = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise ValueError("Unable to resolve target host.") from exc
    if not addresses:
        raise ValueError("Unable to resolve target host.")
    for entry in addresses:
        address = entry[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("Unexpected IP address from DNS.") from exc
        if not ip.is_global:
            raise ValueError("Private, local, reserved or otherwise non-public IP addresses are blocked.")

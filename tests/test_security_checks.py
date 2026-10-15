"""Offline tests: python -m unittest discover -s tests -v"""
import socket
import unittest
from unittest.mock import patch
from security_checks import normalize_url, is_valid_url, ensure_public_target


def public_dns(*args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]


class SecurityChecksTest(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url(" example.com "), "https://example.com")

    def test_accept_https(self):
        self.assertTrue(is_valid_url("https://example.com/login"))

    def test_accept_http(self):
        self.assertTrue(is_valid_url("http://example.com"))

    def test_reject_ftp(self):
        self.assertFalse(is_valid_url("ftp://example.com"))
        self.assertFalse(is_valid_url(normalize_url("ftp://example.com")))

    def test_reject_embedded_credentials(self):
        self.assertFalse(is_valid_url("https://user:pass@example.com"))

    def test_reject_bad_port(self):
        self.assertFalse(is_valid_url("https://example.com:99999"))

    def test_reject_localhost(self):
        with self.assertRaises(ValueError):
            ensure_public_target("http://localhost:5000")

    def test_reject_private_ip(self):
        with patch("security_checks.socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 80))]):
            with self.assertRaises(ValueError):
                ensure_public_target("http://192.168.1.20")

    def test_allow_public_dns_resolution(self):
        with patch("security_checks.socket.getaddrinfo", side_effect=public_dns):
            ensure_public_target("https://example.com")


if __name__ == "__main__":
    unittest.main()

"""Offline regression cases: no HTTP, DNS, TLS, WHOIS, or GUI is started."""
import unittest
from unittest.mock import MagicMock, patch

import requests
import app


def response(url="https://example.com", status=200, headers=None, chunks=(b"hello",)):
    result = requests.Response()
    result.url = url
    result.status_code = status
    result.headers.update(headers or {})
    result.iter_content = MagicMock(return_value=iter(chunks))
    result.close = MagicMock()
    return result


class NetworkAnalysisTests(unittest.TestCase):
    @patch("app.ensure_public_target")
    @patch("app.requests.get")
    def test_small_response_is_retained_and_closed(self, get, guard):
        page = response(chunks=(b"hello", b" world"))
        get.return_value = page
        result, _, error = app.fetch_site(page.url)
        self.assertIsNone(error)
        self.assertEqual(result.content, b"hello world")
        page.close.assert_called_once()
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    @patch("app.ensure_public_target")
    @patch("app.requests.get")
    def test_oversized_decoded_body_is_rejected_and_closed(self, get, guard):
        page = response(chunks=(b"a" * app.MAX_RESPONSE_BYTES, b"b"))
        get.return_value = page
        result, _, error = app.fetch_site(page.url)
        self.assertIsNone(result)
        self.assertIn("2 MiB", error)
        page.close.assert_called_once()

    @patch("app.ensure_public_target")
    @patch("app.requests.get")
    def test_stream_failure_closes_response(self, get, guard):
        page = response()
        page.iter_content.side_effect = requests.exceptions.ConnectionError("interrupted")
        get.return_value = page
        result, _, error = app.fetch_site(page.url)
        self.assertIsNone(result)
        self.assertIn("interrupted", error)
        page.close.assert_called_once()

    @patch("app.ensure_public_target", side_effect=[None, ValueError("private target")])
    @patch("app.requests.get")
    def test_redirect_to_private_target_is_not_fetched(self, get, guard):
        page = response(status=302, headers={"Location": "http://127.0.0.1/admin"})
        get.return_value = page
        result, _, error = app.fetch_site(page.url)
        self.assertIsNone(result)
        self.assertIn("private target", error)
        self.assertEqual(get.call_count, 1)
        page.close.assert_called_once()

    @patch("app.ensure_public_target")
    @patch("app.requests.get", side_effect=requests.exceptions.SSLError("invalid certificate"))
    def test_tls_failure_is_not_retried(self, get, guard):
        result, findings, error = app.fetch_site("https://example.com")
        self.assertIsNone(result)
        self.assertIn("not retried insecurely", error)
        self.assertEqual(get.call_count, 1)
        self.assertEqual(findings[0]["name"], "HTTPS / SSL")

    @patch("app.ensure_public_target")
    @patch("app.requests.get")
    def test_redirect_limit_closes_every_response(self, get, guard):
        pages = [response(status=302, headers={"Location": "/next"}) for _ in range(6)]
        get.side_effect = pages
        result, _, error = app.fetch_site("https://example.com")
        self.assertIsNone(result)
        self.assertIn("Redirect limit", error)
        self.assertEqual(get.call_count, 6)
        for page in pages:
            page.close.assert_called_once()

    @patch("app.check_domain_age", return_value=None)
    @patch("app.check_ssl_certificate", return_value=("safe", "valid", 0))
    @patch("app.dns_resolves", return_value=True)
    def test_static_analysis_passes_custom_https_port(self, dns, certificate, age):
        app.analyze_static("https://example.com:8443/login", [])
        certificate.assert_called_once_with("example.com", 8443)

    @patch("app.ssl.create_default_context")
    @patch("app.socket.create_connection")
    def test_certificate_connection_uses_selected_port(self, connect, context):
        context.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {
            "notAfter": "Oct 17 00:00:00 2030 GMT"
        }
        status, _, _ = app.check_ssl_certificate("example.com", 8443)
        self.assertEqual(status, "safe")
        connect.assert_called_once_with(("example.com", 8443), timeout=5)


if __name__ == "__main__":
    unittest.main()

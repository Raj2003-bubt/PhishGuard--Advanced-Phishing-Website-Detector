"""Incomplete network scans must not look like successful low-risk assessments."""
import unittest
from unittest.mock import patch

import requests
import app


class ScanVerdictTests(unittest.TestCase):
    @patch("app.ensure_public_target")
    @patch("app.analyze_static")
    @patch("app.fetch_site", return_value=(None, [], "connection timed out"))
    def test_failed_fetch_is_incomplete_even_with_low_score(self, fetch, static, guard):
        result = app.run_analysis("https://example.com")
        self.assertLess(result["score"], app.SAFE_THRESHOLD)
        self.assertEqual(result["label"], "INCOMPLETE")
        self.assertEqual(result["color"], app.C_YELLOW)
        self.assertIn("connection timed out", result["findings"][-1]["detail"])

    @patch("app.ensure_public_target")
    @patch("app.analyze_static")
    @patch("app.fetch_site", return_value=(None, [{"status": "danger", "name": "TLS", "detail": "invalid", "points": 20}], "TLS failed"))
    def test_failed_fetch_preserves_all_findings_and_score(self, fetch, static, guard):
        result = app.run_analysis("https://example.com")
        self.assertEqual(result["score"], 35)
        self.assertEqual(result["danger"], 2)
        self.assertEqual(result["label"], "INCOMPLETE")

    @patch("app.ensure_public_target")
    @patch("app.analyze_static")
    @patch("app.fetch_site")
    def test_successful_html_keeps_existing_score_classification(self, fetch, static, guard):
        page = requests.Response()
        page.status_code = 200
        page.url = "https://example.com"
        page.headers["content-type"] = "text/html"
        page._content = b"<html><title>Example</title><p>Information</p></html>"
        page.history = []
        fetch.return_value = page, [], None
        result = app.run_analysis(page.url)
        self.assertEqual(result["label"], "LOW RISK")
        self.assertEqual(result["score"], 0)

    @patch("app.ensure_public_target")
    @patch("app.analyze_static")
    @patch("app.fetch_site")
    def test_error_pages_and_non_html_are_incomplete(self, fetch, static, guard):
        for status, mime in [(404, "text/html"), (200, "application/pdf")]:
            with self.subTest(status=status, mime=mime):
                page = requests.Response()
                page.status_code = status
                page.url = "https://example.com"
                page.headers["content-type"] = mime
                page._content = b"<html><p>No usable page</p></html>"
                page.history = []
                fetch.return_value = page, [], None
                self.assertEqual(app.run_analysis(page.url)["label"], "INCOMPLETE")

    @patch("app.ensure_public_target", side_effect=ValueError("private target"))
    @patch("app.fetch_site")
    def test_blocked_target_remains_blocked_without_fetch(self, fetch, guard):
        result = app.run_analysis("http://127.0.0.1")
        self.assertEqual(result["label"], "BLOCKED")
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()

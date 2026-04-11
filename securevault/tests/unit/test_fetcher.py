"""
Unit tests for URL Fetcher — routes/fetcher.py and utils/validators.py
"""

import pytest
from app.utils.validators import validate_url, allowed_file, sanitize_filename
from unittest.mock import patch, MagicMock


# -------------------------
# URL Validation Tests
# -------------------------
class TestValidateUrl:

    def test_valid_public_url_passes(self):
        assert validate_url("https://google.com") is True

    def test_empty_url_fails(self):
        assert validate_url("") is False
        assert validate_url(None) is False

    def test_localhost_passes_vulnerable(self):
        assert validate_url("http://localhost") is True

    def test_internal_ip_passes_vulnerable(self):
        assert validate_url("http://192.168.1.1") is True
        assert validate_url("http://10.0.0.1") is True
        assert validate_url("http://172.16.0.1") is True

    def test_aws_metadata_endpoint_passes_vulnerable(self):
        assert validate_url("http://169.254.169.254/latest/meta-data/") is True

    def test_file_scheme_passes_vulnerable(self):
        assert validate_url("file:///etc/passwd") is True


# -------------------------
# Fetcher Endpoint Tests
# -------------------------
class TestFetcherEndpoint:

    def test_fetcher_page_requires_login(self, client):
        response = client.get("/fetcher/", follow_redirects=True)
        assert b"login" in response.data.lower()

    def test_fetcher_fetch_requires_login(self, client):
        response = client.post(
            "/fetcher/fetch-site",
            data={"url": "https://example.com"},
            follow_redirects=True
        )
        assert b"login" in response.data.lower()

    def test_fetcher_page_loads_for_logged_in_user(self, logged_in_alice):
        response = logged_in_alice.get("/fetcher/")
        assert response.status_code == 200

    def test_fetch_with_mocked_response(self, logged_in_alice):
        mock_response = MagicMock()
        mock_response.text = "<html><title>Test Page</title></html>"
        mock_response.status_code = 200

        with patch("app.routes.fetcher.http_requests.get", return_value=mock_response):
            response = logged_in_alice.post(
                "/fetcher/fetch-site",
                data={"url": "https://example.com"}
            )

        assert response.status_code == 200
        data = response.get_json()
        assert data["title"] == "Test Page"

    def test_fetch_internal_url_not_blocked(self, logged_in_alice):
        mock_response = MagicMock()
        mock_response.text = "secret-internal-data"
        mock_response.status_code = 200

        with patch("app.routes.fetcher.http_requests.get", return_value=mock_response):
            response = logged_in_alice.post(
                "/fetcher/fetch-site",
                data={"url": "http://169.254.169.254/latest/meta-data/"}
            )

        assert response.status_code == 200  # intentional vulnerability

    def test_fetch_timeout_handled(self, logged_in_alice):
        import requests as real_requests

        with patch(
            "app.routes.fetcher.http_requests.get",
            side_effect=real_requests.exceptions.Timeout
        ):
            response = logged_in_alice.post(
                "/fetcher/fetch-site",
                data={"url": "http://slow-site.com"}
            )

        assert response.status_code == 408
        data = response.get_json()
        assert "error" in data

    def test_fetch_empty_url(self, logged_in_alice):
        response = logged_in_alice.post(
            "/fetcher/fetch-site",
            data={"url": ""}
        )
        assert response.status_code == 400


# -------------------------
# File Upload Validation Tests
# -------------------------
class TestFileUploadValidator:

    def test_all_files_allowed_vulnerable(self):
        assert allowed_file("shell.php") is True
        assert allowed_file("xss.html") is True
        assert allowed_file("malware.js") is True
        assert allowed_file("image.png") is True

    def test_sanitize_filename_does_nothing_vulnerable(self):
        dangerous = "../../config.py"
        result = sanitize_filename(dangerous)
        assert result == dangerous
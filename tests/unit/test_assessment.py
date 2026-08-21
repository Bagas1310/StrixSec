"""
Comprehensive Offline Unit Tests for StrixSec Security Assessment Subsystem.

Ensures zero public network calls during testing via socket/SSL and HTTP mocks.
"""

from __future__ import annotations

import socket
import ssl
from unittest.mock import MagicMock, patch

import httpx
import pytest

from strixsec.assessment.cookies import evaluate_cookies
from strixsec.assessment.engine import AssessmentEngine
from strixsec.assessment.headers import evaluate_security_headers
from strixsec.assessment.metadata import inspect_metadata
from strixsec.assessment.tls import inspect_tls
from strixsec.core.errors import ScopeValidationError
from strixsec.recon.models import HTTPResult
from strixsec.scope.models import ScopeConfig, ScopeEntry, TargetType
from strixsec.scope.validator import ScopeValidator

# --- Security Headers Tests ---


def test_security_headers_all_present() -> None:
    http_res = HTTPResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        },
    )
    result = evaluate_security_headers(http_res)
    assert result.target == "https://example.com"
    assert len(result.checks) == 6
    assert all(c.is_present for c in result.checks)


def test_security_headers_missing() -> None:
    http_res = HTTPResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
    )
    result = evaluate_security_headers(http_res)
    assert result.target == "https://example.com"
    assert len(result.checks) == 6
    assert all(not c.is_present for c in result.checks)


# --- TLS Inspection Tests (Mocked Socket/SSL) ---


@patch("socket.create_connection")
def test_tls_inspection_success(mock_create_conn: MagicMock) -> None:
    mock_sock = MagicMock()
    mock_ssock = MagicMock()

    mock_create_conn.return_value.__enter__.return_value = mock_sock
    mock_ssock.__enter__.return_value = mock_ssock

    # Mock cert dict
    mock_cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "notBefore": "May 20 12:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    with patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
        res = inspect_tls("example.com")

    assert res.status == "SUCCESS"
    assert res.tls_version == "TLSv1.3"
    assert res.cert_info is not None
    assert res.cert_info.subject.get("commonName") == "example.com"
    assert res.cert_info.issuer.get("organizationName") == "DigiCert Inc"
    assert res.cert_info.hostname_matches is True
    assert res.cert_info.is_expired is False


@patch("socket.create_connection", side_effect=socket.timeout)
def test_tls_inspection_timeout(mock_create_conn: MagicMock) -> None:
    res = inspect_tls("timeout-example.com")
    assert res.status == "TIMEOUT"
    assert "timed out" in (res.error or "")


@patch("socket.create_connection")
def test_tls_verification_failed(mock_create_conn: MagicMock) -> None:
    err = ssl.SSLCertVerificationError("certificate has expired")
    err.verify_message = "certificate has expired"

    with patch("ssl.SSLContext.wrap_socket", side_effect=err):
        res = inspect_tls("expired-example.com")

    assert res.status == "VERIFICATION_FAILED"
    assert "verification failed" in (res.error or "").lower()


# --- Cookie Security & Value Redaction Tests ---


def test_cookie_security_and_mandatory_redaction() -> None:
    cookie_val = "sess_token=SECRET_SUPER_CONFIDENTIAL_12345; Secure; HttpOnly; SameSite=Strict"
    http_res = HTTPResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={"Set-Cookie": cookie_val},
    )

    result = evaluate_cookies(http_res)
    assert len(result.cookies) == 1
    c = result.cookies[0]

    assert c.cookie_name == "sess_token"
    assert c.secure is True
    assert c.httponly is True
    assert c.samesite == "Strict"

    # MANDATORY SECURITY ASSERTION: Secret value must NEVER appear in output string!
    assert "SECRET_SUPER_CONFIDENTIAL_12345" not in c.redacted_header
    assert "SECRET_SUPER_CONFIDENTIAL_12345" not in str(result)
    assert "<REDACTED>" in c.redacted_header
    assert c.redacted_header == "sess_token=<REDACTED>; Secure; HttpOnly; SameSite=Strict"


# --- Safe Public Metadata Tests ---


def test_metadata_inspection_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "robots.txt" in request.url.path:
            return httpx.Response(200, content=b"User-agent: *\nDisallow: /admin/", request=request)
        elif "security.txt" in request.url.path:
            return httpx.Response(
                200, content=b"Contact: mailto:security@example.com", request=request
            )
        return httpx.Response(404, request=request)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    config = ScopeConfig(
        allowed_targets=[
            ScopeEntry(
                raw_target="example.com",
                normalized_target="example.com",
                target_type=TargetType.EXACT_DOMAIN,
            )
        ]
    )

    with patch("strixsec.scope.storage.ScopeStorage.load_scope", return_value=config):
        res = inspect_metadata("example.com", client=client)

    assert res.robots_found is True
    assert "User-agent: *" in (res.robots_content or "")
    assert res.security_txt_found is True
    assert "mailto:security@example.com" in (res.security_txt_content or "")


# --- Critical Security Test: Out of Scope Assessment Protection ---


def test_assessment_out_of_scope_target_causes_zero_network_requests() -> None:
    """Security Test: Out-of-scope target causes ZERO socket/HTTP calls."""
    config = ScopeConfig()  # Empty scope -> All targets out of scope!
    validator = ScopeValidator(config)
    engine = AssessmentEngine(validator=validator)

    mock_socket = MagicMock()
    mock_http = MagicMock()

    with (
        patch("socket.create_connection", mock_socket),
        patch("httpx.Client.stream", mock_http),
    ):
        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_headers("unauthorized-target.com")

        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_tls("unauthorized-target.com")

        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_cookies("unauthorized-target.com")

        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_metadata("unauthorized-target.com")

        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_full_assessment("unauthorized-target.com")

    # Assert ZERO socket / HTTP network calls were attempted!
    assert mock_socket.call_count == 0
    assert mock_http.call_count == 0

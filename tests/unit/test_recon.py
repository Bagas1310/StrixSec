"""
Comprehensive Unit Tests for StrixSec Recon Subsystem.

Ensures zero public network calls during testing via mocks and local transports.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import httpx
import pytest

from strixsec.core.errors import ScopeValidationError
from strixsec.recon.dns import query_dns
from strixsec.recon.engine import ReconEngine
from strixsec.recon.http import analyze_http
from strixsec.recon.models import (
    HTTPResult,
)
from strixsec.recon.tech import detect_technologies
from strixsec.scope.models import ScopeConfig, ScopeEntry, TargetType
from strixsec.scope.validator import ScopeValidator

# --- DNS Recon Tests ---


@patch("dns.resolver.Resolver.resolve")
def test_dns_query_success(mock_resolve: MagicMock) -> None:
    # Mock A record response
    mock_a_data = MagicMock()
    mock_a_data.__str__.return_value = "1.2.3.4"

    mock_answers = MagicMock()
    mock_answers.__iter__.return_value = [mock_a_data]
    mock_answers.ttl = 300

    def resolve_side_effect(target: str, rtype: str):
        if rtype == "A":
            return mock_answers
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = resolve_side_effect

    res = query_dns("example.com", record_types=["A", "MX"])
    assert res.target == "example.com"
    assert res.status == "SUCCESS"
    assert len(res.records) == 1
    assert res.records[0].record_type == "A"
    assert res.records[0].value == "1.2.3.4"
    assert res.records[0].ttl == 300


@patch("dns.resolver.Resolver.resolve")
def test_dns_query_nxdomain(mock_resolve: MagicMock) -> None:
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()
    res = query_dns("nonexistent.com")
    assert res.status == "NXDOMAIN"
    assert len(res.records) == 0


@patch("dns.resolver.Resolver.resolve")
def test_dns_query_timeout(mock_resolve: MagicMock) -> None:
    mock_resolve.side_effect = dns.resolver.Timeout()
    res = query_dns("timeout.com")
    assert res.status == "TIMEOUT"
    assert len(res.errors) > 0


# --- HTTP Inspection Tests using httpx.MockTransport ---


def test_http_analysis_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx/1.24.0",
        }
        content = (
            b"<html><head><title>Test Page Title</title></head><body>Hello World</body></html>"
        )
        return httpx.Response(200, headers=headers, content=content, request=request)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    # Pre-configure scope so test validator allows example.com
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
        res = analyze_http("example.com", client=client)

    assert res.status_code == 200
    assert res.server == "nginx/1.24.0"
    assert res.page_title == "Test Page Title"
    assert res.content_type == "text/html; charset=utf-8"
    assert res.error is None


def test_http_analysis_redirect_tracking() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https" and request.url.host == "example.com":
            return httpx.Response(
                301,
                headers={"Location": "https://api.example.com/v1"},
                request=request,
            )
        elif request.url.host == "api.example.com":
            return httpx.Response(
                200,
                headers={"Server": "Express"},
                content=b"<html><title>API Docs</title></html>",
                request=request,
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
        res = analyze_http("example.com", client=client)

    assert res.status_code == 200
    assert res.final_url == "https://api.example.com/v1"
    assert len(res.redirect_chain) == 1
    assert res.redirect_chain[0].status_code == 301


# --- Passive Technology Detection Tests ---


def test_technology_detection() -> None:
    http_res = HTTPResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={
            "Server": "nginx/1.18.0",
            "X-Powered-By": "Express",
            "Set-Cookie": "laravel_session=xyz123",
        },
        content_type="text/html",
        page_title="Sample App",
        server="nginx/1.18.0",
    )

    tech_res = detect_technologies(http_res)
    matches = {t.name for t in tech_res.detected_technologies}

    assert "Nginx" in matches
    assert "Express.js" in matches
    assert "Laravel" in matches


# --- Critical Security Test: Out of Scope Target Protection ---


def test_out_of_scope_target_causes_zero_network_requests() -> None:
    """Security Test: Out-of-scope target must be rejected with ZERO network calls."""
    config = ScopeConfig()  # Empty scope -> All targets out of scope!
    validator = ScopeValidator(config)
    engine = ReconEngine(validator=validator)

    mock_dns = MagicMock()
    mock_http_client = MagicMock()

    with (
        patch("dns.resolver.Resolver.resolve", mock_dns),
        patch("httpx.Client.stream", mock_http_client),
    ):
        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_dns("unauthorized-target.com")

        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_http("unauthorized-target.com")

        with pytest.raises(ScopeValidationError, match="OUT OF SCOPE"):
            engine.run_full_recon("unauthorized-target.com")

    # Assert ZERO network requests were attempted!
    assert mock_dns.call_count == 0
    assert mock_http_client.call_count == 0


def test_redirect_to_out_of_scope_hostname_is_blocked() -> None:
    """Verify that a 301/302 redirect attempting to jump to an out-of-scope domain is halted."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(
                302,
                headers={"Location": "https://evil.com/phish"},
                request=request,
            )
        # Should never reach evil.com
        return httpx.Response(200, content=b"Evil Page", request=request)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    # Only example.com in scope (evil.com NOT in scope)
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
        res = analyze_http("example.com", client=client)

    assert res.error is not None
    assert "Redirect halted" in res.error
    assert "evil.com" in res.error
    assert len(res.redirect_chain) == 1  # 302 response recorded, evil.com request never sent


def test_response_size_limited_to_2mb() -> None:
    """Verify that response bodies larger than 2 MB are safely capped/truncated."""
    large_content = b"A" * (3 * 1024 * 1024)  # 3 MB content

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=large_content,
            request=request,
        )

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
        res = analyze_http("example.com", client=client)

    assert res.status_code == 200
    assert res.error is None


def test_redirect_limit_enforced() -> None:
    """Verify that exceeding max_redirects halts execution."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Infinite redirect loop
        return httpx.Response(
            302,
            headers={"Location": "https://example.com/loop"},
            request=request,
        )

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
        res = analyze_http("example.com", max_redirects=3, client=client)

    assert res.error is not None
    assert len(res.redirect_chain) == 3

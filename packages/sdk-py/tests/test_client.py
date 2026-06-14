"""Tests for the AgentAuth Python SDK.

These use ``httpx.MockTransport`` so no real network is touched. The mock
handler inspects the request method + path and returns canned envelopes,
letting us assert headers, body shaping, pagination, target resolution, and
the non-2xx -> AgentAuthError mapping.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

import httpx
import pytest

from agentauth import AgentAuthClient, AgentAuthError, HumanClient

BASE = "https://api.test.local"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def make_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    """Wrap a request handler as an httpx MockTransport."""
    return httpx.MockTransport(handler)


def ok(payload: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


def envelope_error(status: int, code: str, message: str,
                   request_id: str = "req_1", details: Any = None) -> httpx.Response:
    body: Dict[str, Any] = {
        "error": {"code": code, "message": message, "requestId": request_id}
    }
    if details is not None:
        body["error"]["details"] = details
    return httpx.Response(status, json=body)


def body_of(request: httpx.Request) -> Dict[str, Any]:
    return json.loads(request.content.decode() or "{}")


# --------------------------------------------------------------------------
# HumanClient — auth
# --------------------------------------------------------------------------

def test_register_posts_email_and_password():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/principals"
        seen["body"] = body_of(request)
        return ok({"id": "p1", "email": "me@example.com"}, status=201)

    client = HumanClient(BASE, transport=make_transport(handler))
    out = client.register("me@example.com", "pw")
    assert out == {"id": "p1", "email": "me@example.com"}
    assert seen["body"] == {"email": "me@example.com", "password": "pw"}


def test_login_stores_token_and_sets_auth_header():
    captured_headers: List[Optional[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.append(request.headers.get("authorization"))
        if request.url.path == "/v1/auth/login":
            return ok({"token": "jwt123", "tokenType": "Bearer",
                       "expiresAt": "2030-01-01T00:00:00Z"})
        if request.url.path == "/v1/passports":
            return ok({"id": "pp1", "name": "work", "createdAt": "now"}, status=201)
        raise AssertionError(request.url.path)

    client = HumanClient(BASE, transport=make_transport(handler))
    login = client.login("me@example.com", "pw")
    assert login["token"] == "jwt123"
    assert client.token == "jwt123"

    # Subsequent call must carry the Authorization header.
    client.create_passport("work")
    # First request (login) had no auth header; second (passport) does.
    assert captured_headers[0] is None
    assert captured_headers[1] == "Bearer jwt123"


def test_constructor_token_sets_auth_header():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return ok({"items": [], "pagination": {"limit": 50, "offset": 0,
                                                "total": 0, "returned": 0}})

    client = HumanClient(BASE, token="pretoken", transport=make_transport(handler))
    client.list_passports()
    assert seen["auth"] == "Bearer pretoken"


def test_logout_clears_local_auth_state():
    def handler(request: httpx.Request) -> httpx.Response:
        return ok({"loggedOut": True})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    out = client.logout()
    assert out == {"loggedOut": True}
    assert client.token is None
    assert "authorization" not in client._http.headers


# --------------------------------------------------------------------------
# HumanClient — passports / credentials / agents / audit
# --------------------------------------------------------------------------

def test_deposit_credential_maps_camelcase_fields():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/passports/pp1/credentials"
        seen["body"] = body_of(request)
        return ok({"id": "c1", "target": "github.com", "label": "GH",
                   "type": "api_key", "metadata": {}, "expiresAt": None,
                   "createdAt": "now"}, status=201)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    out = client.deposit_credential(
        "pp1",
        target="github.com",
        label="GH",
        type="api_key",
        secret="ghp_xxx",
        metadata={"env": "prod"},
        expires_at="2031-01-01T00:00:00Z",
    )
    assert out["id"] == "c1"
    assert seen["body"] == {
        "target": "github.com",
        "label": "GH",
        "type": "api_key",
        "secret": "ghp_xxx",
        "metadata": {"env": "prod"},
        "expiresAt": "2031-01-01T00:00:00Z",
    }


def test_deposit_credential_omits_optional_fields_when_absent():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        return ok({"id": "c2"}, status=201)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    client.deposit_credential("pp1", target="x", label="l", type="password",
                              secret="s")
    assert "metadata" not in seen["body"]
    assert "expiresAt" not in seen["body"]


def test_issue_agent_sends_scopes_and_returns_apikey():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/agents"
        seen["body"] = body_of(request)
        return ok({"id": "a1", "name": "ci", "scopes": ["vault:read"],
                   "apiKey": "aa_uuid.secret", "warning": "shown once"},
                  status=201)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    out = client.issue_agent(passport_id="pp1", name="ci",
                             scopes=["vault:read", "vault:use", "target:github.com"])
    assert out["apiKey"] == "aa_uuid.secret"
    assert seen["body"] == {
        "passportId": "pp1",
        "name": "ci",
        "scopes": ["vault:read", "vault:use", "target:github.com"],
    }


def test_revoke_agent_posts_to_revoke_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/agents/a1/revoke"
        return ok({"id": "a1", "revoked": True})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    assert client.revoke_agent("a1") == {"id": "a1", "revoked": True}


def test_list_passports_forwards_pagination_params():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["query"] = dict(request.url.params)
        return ok({"items": [], "pagination": {"limit": 5, "offset": 10,
                                                "total": 0, "returned": 0}})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    client.list_passports(limit=5, offset=10)
    assert seen["query"] == {"limit": "5", "offset": "10"}


def test_list_audit_and_verify_audit():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/audit":
            return ok({"items": [{"seq": 1}], "pagination": {}})
        if request.url.path == "/v1/audit/verify":
            return ok({"ok": True, "count": 1, "brokenAtSeq": None})
        raise AssertionError(request.url.path)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    assert client.list_audit()["items"] == [{"seq": 1}]
    assert client.verify_audit() == {"ok": True, "count": 1, "brokenAtSeq": None}


# --------------------------------------------------------------------------
# AgentAuthClient — data plane
# --------------------------------------------------------------------------

def test_agent_client_requires_api_key():
    with pytest.raises(ValueError):
        AgentAuthClient(BASE, "")


def test_agent_list_credentials_sends_bearer_key():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        assert request.url.path == "/v1/vault/credentials"
        return ok({"items": [{"id": "c1", "target": "github.com"}],
                   "pagination": {"limit": 100, "offset": 0,
                                  "total": 1, "returned": 1}})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = client.list_credentials()
    assert page["items"][0]["id"] == "c1"
    assert seen["auth"] == "Bearer aa_key.secret"


def test_use_credential_by_id_hits_use_endpoint_directly():
    calls: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.url.path == "/v1/vault/credentials/c1/use"
        assert request.method == "POST"
        return ok({"id": "c1", "target": "github.com", "label": "GH",
                   "type": "api_key", "metadata": {}, "secret": "ghp_xxx"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.use_credential("c1")
    assert out["secret"] == "ghp_xxx"
    # Only the direct use call — no listing needed when the id resolves.
    assert calls == ["/v1/vault/credentials/c1/use"]


def test_use_credential_by_target_resolves_via_listing():
    """A target that isn't an id: use 404s, then we list and resolve."""
    calls: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        # 1) direct use of the literal "github.com" -> 404 (not an id)
        if request.url.path == "/v1/vault/credentials/github.com/use":
            return envelope_error(404, "not_found", "no such credential")
        # 2) listing to resolve the target
        if request.url.path == "/v1/vault/credentials":
            return ok({
                "items": [
                    {"id": "c-other", "target": "gitlab.com"},
                    {"id": "c-gh", "target": "github.com"},
                ],
                "pagination": {"limit": 100, "offset": 0, "total": 2, "returned": 2},
            })
        # 3) use of the resolved id
        if request.url.path == "/v1/vault/credentials/c-gh/use":
            return ok({"id": "c-gh", "target": "github.com", "label": "GH",
                       "type": "api_key", "metadata": {}, "secret": "resolved"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.use_credential("github.com")
    assert out["id"] == "c-gh"
    assert out["secret"] == "resolved"
    assert calls == [
        "POST /v1/vault/credentials/github.com/use",
        "GET /v1/vault/credentials",
        "POST /v1/vault/credentials/c-gh/use",
    ]


def test_use_credential_target_not_found_raises_404():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/use"):
            return envelope_error(404, "not_found", "no such credential")
        if request.url.path == "/v1/vault/credentials":
            return ok({"items": [{"id": "c1", "target": "gitlab.com"}],
                       "pagination": {"limit": 100, "offset": 0,
                                      "total": 1, "returned": 1}})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.use_credential("nope.com")
    assert ei.value.status == 404
    assert ei.value.code == "not_found"


def test_use_credential_target_paginates_until_found():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/vault/credentials/host.com/use":
            return envelope_error(404, "not_found", "x")
        if request.url.path == "/v1/vault/credentials":
            offset = int(request.url.params.get("offset", "0"))
            if offset == 0:
                return ok({"items": [{"id": "a", "target": "one.com"}],
                           "pagination": {"limit": 1, "offset": 0,
                                          "total": 2, "returned": 1}})
            return ok({"items": [{"id": "b", "target": "host.com"}],
                       "pagination": {"limit": 1, "offset": 1,
                                      "total": 2, "returned": 1}})
        if request.url.path == "/v1/vault/credentials/b/use":
            return ok({"id": "b", "secret": "deep"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.use_credential("host.com", limit=1)
    assert out == {"id": "b", "secret": "deep"}


def test_use_credential_by_id_non_404_error_propagates():
    """A 403 on a real id must NOT trigger target-resolution fallback."""
    calls: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return envelope_error(403, "forbidden", "scope vault:use required")

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.use_credential("c1")
    assert ei.value.status == 403
    assert ei.value.code == "forbidden"
    # No listing fallback happened.
    assert calls == ["/v1/vault/credentials/c1/use"]


# --------------------------------------------------------------------------
# Error mapping
# --------------------------------------------------------------------------

def test_error_envelope_is_mapped_to_structured_exception():
    def handler(request: httpx.Request) -> httpx.Response:
        return envelope_error(401, "unauthorized", "bad token",
                              request_id="req_abc",
                              details={"field": "authorization"})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.list_passports()
    err = ei.value
    assert err.status == 401
    assert err.code == "unauthorized"
    assert err.message == "bad token"
    assert err.request_id == "req_abc"
    assert err.details == {"field": "authorization"}
    assert "401" in str(err)


def test_error_without_envelope_falls_back_to_header_request_id():
    def handler(request: httpx.Request) -> httpx.Response:
        # Non-JSON body (e.g. a proxy 502) + request id only in the header.
        return httpx.Response(502, text="<html>bad gateway</html>",
                              headers={"x-request-id": "edge_42"})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.verify_audit()
    err = ei.value
    assert err.status == 502
    assert err.code == "http_error"
    assert err.request_id == "edge_42"


def test_503_fail_closed_on_vault_use():
    def handler(request: httpx.Request) -> httpx.Response:
        return envelope_error(503, "unavailable", "authorization store unreachable")

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.use_credential("c1")
    assert ei.value.status == 503
    assert ei.value.code == "unavailable"


def test_network_failure_is_wrapped_as_agentautherror():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.list_passports()
    assert ei.value.status == 0
    assert ei.value.code == "network_error"


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------

def test_base_url_trailing_slash_is_normalised():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{BASE}/v1/passports"
        return ok({"items": [], "pagination": {}})

    client = HumanClient(BASE + "/", token="t", transport=make_transport(handler))
    client.list_passports()


def test_context_manager_closes_client():
    def handler(request: httpx.Request) -> httpx.Response:
        return ok({"items": [], "pagination": {}})

    with HumanClient(BASE, token="t", transport=make_transport(handler)) as client:
        client.list_passports()
    assert client._http.is_closed


def test_empty_body_success_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    # revoke that returns 204 with no body should not blow up on .json()
    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    assert client.revoke_agent("a1") is None


def test_use_credential_202_raises_approval_pending():
    from agentauth import ApprovalPendingError

    def handler(request: httpx.Request) -> httpx.Response:
        # The use endpoint returns 202 when the credential requires approval.
        return httpx.Response(
            202, json={"status": "pending", "requestId": "req_99", "message": "awaiting approval"}
        )

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(ApprovalPendingError) as exc:
        client.use_credential("33333333-3333-4333-8333-333333333333")
    assert exc.value.status == 202
    assert exc.value.code == "approval_pending"
    assert exc.value.request_id == "req_99"


def test_human_approval_methods():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        if request.url.path.endswith("/approve") or request.url.path.endswith("/deny"):
            return ok({"id": "r1", "status": "approved", "credentialId": "c1",
                       "agentId": "a1", "passportId": "p1",
                       "createdAt": "t", "expiresAt": "t2"})
        return ok({"items": [], "pagination": {"limit": 50, "offset": 0, "total": 0, "returned": 0}})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    page = client.list_approvals()
    assert "items" in page
    approved = client.approve_request("r1")
    assert approved["status"] == "approved"
    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/approvals/r1/approve"
    denied = client.deny_request("r1")
    assert seen["path"] == "/v1/approvals/r1/deny"
    assert denied["id"] == "r1"

"""Tests for the AgentAuth Python SDK.

These use ``httpx.MockTransport`` so no real network is touched. The mock
handler inspects the request method + path and returns canned envelopes,
letting us assert headers, body shaping, pagination, target resolution, and
the non-2xx -> AgentAuthError mapping.
"""

from __future__ import annotations

import json
import re
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
            return ok({"ok": True})
        raise AssertionError(request.url.path)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    assert client.list_audit()["items"] == [{"seq": 1}]
    assert client.verify_audit() == {"ok": True}


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
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.url.path == f"/v1/vault/credentials/{cid}/use"
        assert request.method == "POST"
        return ok({"id": cid, "target": "github.com", "label": "GH",
                   "type": "api_key", "metadata": {}, "secret": "ghp_xxx"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.use_credential(cid)
    assert out["secret"] == "ghp_xxx"
    # A UUID is used directly — no listing needed.
    assert calls == [f"/v1/vault/credentials/{cid}/use"]


def test_use_credential_by_target_resolves_via_listing():
    """A non-UUID target is resolved via the listing first (never POSTed to a
    uuid-typed :id route), then used by the resolved id."""
    calls: List[str] = []
    gh = "22222222-2222-4222-8222-222222222222"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        # 1) listing to resolve the target
        if request.url.path == "/v1/vault/credentials":
            return ok({
                "items": [
                    {"id": "c-other", "target": "gitlab.com"},
                    {"id": gh, "target": "github.com"},
                ],
                "pagination": {"limit": 100, "offset": 0, "total": 2, "returned": 2},
            })
        # 2) use of the resolved id
        if request.url.path == f"/v1/vault/credentials/{gh}/use":
            return ok({"id": gh, "target": "github.com", "label": "GH",
                       "type": "api_key", "metadata": {}, "secret": "resolved"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.use_credential("github.com")
    assert out["id"] == gh
    assert out["secret"] == "resolved"
    # No direct POST to /github.com/use — the target is resolved first.
    assert calls == [
        "GET /v1/vault/credentials",
        f"POST /v1/vault/credentials/{gh}/use",
    ]


def test_use_credential_target_is_case_insensitive():
    """A mixed-case host still resolves the lowercased listing entry (the server
    stores targets lowercased)."""
    gh = "22222222-2222-4222-8222-222222222222"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/vault/credentials":
            return ok({
                "items": [{"id": gh, "target": "github.com"}],
                "pagination": {"limit": 100, "offset": 0, "total": 1, "returned": 1},
            })
        if request.url.path == f"/v1/vault/credentials/{gh}/use":
            return ok({"id": gh, "target": "github.com", "secret": "resolved"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.use_credential("GitHub.COM")
    assert out["id"] == gh
    assert out["secret"] == "resolved"
    # Trailing dot + whitespace are canonicalized the same way the server deposits.
    assert client.use_credential("  github.com.  ")["id"] == gh


def test_use_credential_target_matches_by_host():
    """A bare host resolves a URL-form stored target (server lists/authorizes by host)."""
    cid = "33333333-3333-4333-8333-333333333333"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/vault/credentials":
            return ok({
                "items": [{"id": cid, "target": "https://api.github.com/v1"}],
                "pagination": {"limit": 100, "offset": 0, "total": 1, "returned": 1},
            })
        if request.url.path == f"/v1/vault/credentials/{cid}/use":
            return ok({"id": cid, "secret": "resolved"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    assert client.use_credential("api.github.com")["id"] == cid


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
    """A 403 on a UUID id goes straight to /use; no listing fallback."""
    calls: List[str] = []
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return envelope_error(403, "forbidden", "scope vault:use required")

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.use_credential(cid)
    assert ei.value.status == 403
    assert ei.value.code == "forbidden"
    # No listing fallback happened.
    assert calls == [f"/v1/vault/credentials/{cid}/use"]


# --------------------------------------------------------------------------
# AgentAuthClient — proxy mode
# --------------------------------------------------------------------------

def test_proxy_by_id_posts_proxy_path():
    seen: Dict[str, Any] = {}

    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = body_of(request)
        assert request.url.path == f"/v1/vault/credentials/{cid}/proxy"
        assert request.method == "POST"
        return ok({"status": 200, "headers": {"content-type": "application/json"},
                   "body": '{"ok":true}'})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.proxy(
        cid,
        method="POST",
        path="/repos/me/x/issues",
        query={"state": "open"},
        headers={"accept": "application/vnd.github+json"},
        body='{"title":"hi"}',
    )
    assert out["status"] == 200
    assert out["body"] == '{"ok":true}'
    assert seen["body"] == {
        "method": "POST",
        "path": "/repos/me/x/issues",
        "query": {"state": "open"},
        "headers": {"accept": "application/vnd.github+json"},
        "body": '{"title":"hi"}',
    }


def test_proxy_omits_none_fields_and_defaults():
    seen: Dict[str, Any] = {}

    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        assert request.url.path == f"/v1/vault/credentials/{cid}/proxy"
        return ok({"status": 204, "headers": {}, "body": ""})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    client.proxy(cid)
    # Defaults applied for method/path; optional fields omitted entirely.
    assert seen["body"] == {"method": "GET", "path": "/"}
    assert "query" not in seen["body"]
    assert "headers" not in seen["body"]
    assert "body" not in seen["body"]


def test_proxy_by_target_resolves_then_proxies():
    """A non-UUID target is resolved via the listing first, then proxied by id."""
    calls: List[str] = []
    gh = "22222222-2222-4222-8222-222222222222"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        # 1) listing to resolve the target
        if request.url.path == "/v1/vault/credentials":
            return ok({
                "items": [
                    {"id": "c-other", "target": "gitlab.com"},
                    {"id": gh, "target": "github.com"},
                ],
                "pagination": {"limit": 100, "offset": 0, "total": 2, "returned": 2},
            })
        # 2) proxy of the resolved id
        if request.url.path == f"/v1/vault/credentials/{gh}/proxy":
            return ok({"status": 200, "headers": {}, "body": "resolved"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.proxy("github.com", path="/user")
    assert out["body"] == "resolved"
    # No direct POST to /github.com/proxy — the target is resolved first.
    assert calls == [
        "GET /v1/vault/credentials",
        f"POST /v1/vault/credentials/{gh}/proxy",
    ]


def test_proxy_by_id_non_404_error_propagates():
    """A 403 (e.g. missing vault:proxy) on a UUID id propagates without listing."""
    calls: List[str] = []
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return envelope_error(403, "forbidden", "scope vault:proxy required")

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(AgentAuthError) as ei:
        client.proxy(cid)
    assert ei.value.status == 403
    assert ei.value.code == "forbidden"
    assert calls == [f"/v1/vault/credentials/{cid}/proxy"]


def test_proxy_202_raises_approval_pending():
    from agentauth import ApprovalPendingError

    def handler(request: httpx.Request) -> httpx.Response:
        # The proxy endpoint returns 202 when the target requires approval.
        return httpx.Response(
            202, json={"status": "pending", "requestId": "req_77",
                       "message": "awaiting approval"}
        )

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(ApprovalPendingError) as exc:
        client.proxy("33333333-3333-4333-8333-333333333333", path="/me")
    assert exc.value.status == 202
    assert exc.value.code == "approval_pending"
    assert exc.value.request_id == "req_77"


def test_deposit_credential_includes_injection_when_present():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        return ok({"id": "c9"}, status=201)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    client.deposit_credential(
        "pp1", target="api.x.com", label="X", type="api_key", secret="s",
        injection={"mode": "header", "name": "X-Api-Key", "prefix": "Token "},
    )
    assert seen["body"]["injection"] == {
        "mode": "header", "name": "X-Api-Key", "prefix": "Token ",
    }


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
        client.use_credential("11111111-1111-4111-8111-111111111111")
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


def test_revoke_agent_returns_revoked_dict():
    # The real server returns 200 {id, revoked: true} (src/routes/agents.ts), so the
    # SDK surfaces that dict — it does NOT return None.
    aid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        return ok({"id": aid, "revoked": True})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    assert client.revoke_agent(aid) == {"id": aid, "revoked": True}


def test_empty_body_success_returns_none():
    # Defensive coverage of the SDK's empty-body branch. No current server endpoint
    # returns 204/empty, so this guards only hypothetical/edge responses.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    assert client.list_passports() is None


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


def test_deposit_credential_forwards_policy_fields():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        return ok({"id": "c-policy"}, status=201)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    client.deposit_credential(
        "pp1", target="api.x.com", label="X", type="api_key", secret="s",
        max_uses=5,
        allowed_from="2030-01-01T00:00:00Z",
        allowed_until="2031-01-01T00:00:00Z",
        require_approval=True,
    )
    assert seen["body"]["maxUses"] == 5
    assert seen["body"]["allowedFrom"] == "2030-01-01T00:00:00Z"
    assert seen["body"]["allowedUntil"] == "2031-01-01T00:00:00Z"
    assert seen["body"]["requireApproval"] is True


def test_deposit_credential_omits_policy_fields_when_absent():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        return ok({"id": "c2"}, status=201)

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    client.deposit_credential("pp1", target="x", label="l", type="password",
                              secret="s")
    for k in ("maxUses", "allowedFrom", "allowedUntil", "requireApproval"):
        assert k not in seen["body"]


# --------------------------------------------------------------------------
# HumanClient — mTLS bind + OAuth start
# --------------------------------------------------------------------------

def test_bind_agent_mtls_with_cert_pem():
    seen: Dict[str, Any] = {}
    aid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"/v1/agents/{aid}/mtls"
        seen["body"] = body_of(request)
        return ok({"id": aid, "certFingerprint": "ab" * 32})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    out = client.bind_agent_mtls(aid, cert_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")
    assert out == {"id": aid, "certFingerprint": "ab" * 32}
    assert seen["body"] == {
        "certPem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"
    }
    assert "fingerprint" not in seen["body"]


def test_bind_agent_mtls_with_fingerprint():
    seen: Dict[str, Any] = {}
    aid = "11111111-1111-4111-8111-111111111111"
    fp = "cd" * 32

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        return ok({"id": aid, "certFingerprint": fp})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    out = client.bind_agent_mtls(aid, fingerprint=fp)
    assert out["certFingerprint"] == fp
    assert seen["body"] == {"fingerprint": fp}
    assert "certPem" not in seen["body"]


def test_start_oauth_returns_authorize_url_and_state():
    seen: Dict[str, Any] = {}
    pid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"/v1/passports/{pid}/oauth/github/start"
        seen["body"] = body_of(request)
        return ok({"authorizeUrl": "https://github.com/login/oauth/authorize?x=1",
                   "state": "st_123"})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    out = client.start_oauth(pid, "github", target="github.com", label="GH OAuth")
    assert out == {"authorizeUrl": "https://github.com/login/oauth/authorize?x=1",
                   "state": "st_123"}
    assert seen["body"] == {"target": "github.com", "label": "GH OAuth"}


def test_start_oauth_omits_optional_fields_when_absent():
    seen: Dict[str, Any] = {}
    pid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = body_of(request)
        return ok({"authorizeUrl": "https://x/auth", "state": "st"})

    client = HumanClient(BASE, token="t", transport=make_transport(handler))
    client.start_oauth(pid, "google")
    assert seen["body"] == {}


# --------------------------------------------------------------------------
# AgentAuthClient — browser-login plan + apply
# --------------------------------------------------------------------------

def test_get_browser_login_plan_by_id_hits_endpoint_directly():
    calls: List[str] = []
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "cookie", "target": "github.com",
            "url": "https://github.com",
            "cookies": [{"name": "sid", "value": "SECRET", "path": "/"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        assert request.url.path == f"/v1/vault/credentials/{cid}/browser-login"
        assert request.method == "POST"
        # The liability path requests the raw endpoint (vault:browser:raw gated).
        assert request.url.params.get("raw") == "true"
        return ok(plan)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.get_browser_login_plan(cid)
    assert out == plan
    assert calls == [f"POST /v1/vault/credentials/{cid}/browser-login"]


def test_get_browser_login_plan_by_target_resolves_via_listing():
    calls: List[str] = []
    gh = "22222222-2222-4222-8222-222222222222"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == "/v1/vault/credentials":
            return ok({"items": [{"id": "c-other", "target": "gitlab.com"},
                                  {"id": gh, "target": "github.com"}],
                       "pagination": {"limit": 100, "offset": 0,
                                      "total": 2, "returned": 2}})
        if request.url.path == f"/v1/vault/credentials/{gh}/browser-login":
            return ok({"mode": "header", "target": "github.com",
                       "url": "https://github.com", "headers": {"Authorization": "x"}})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    out = client.get_browser_login_plan("github.com")
    assert out["mode"] == "header"
    assert calls == [
        "GET /v1/vault/credentials",
        f"POST /v1/vault/credentials/{gh}/browser-login",
    ]


def test_get_browser_login_plan_202_raises_approval_pending():
    from agentauth import ApprovalPendingError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "pending", "requestId": "req_bl",
                                         "message": "awaiting approval"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    with pytest.raises(ApprovalPendingError) as exc:
        client.get_browser_login_plan("33333333-3333-4333-8333-333333333333")
    assert exc.value.status == 202
    assert exc.value.request_id == "req_bl"


class FakeContext:
    """Records context-level Playwright calls."""

    def __init__(self) -> None:
        self.added_cookies: Any = None
        self.extra_headers: Any = None
        self.cookies_cleared = False

    def add_cookies(self, cookies: Any) -> None:
        self.added_cookies = cookies

    def set_extra_http_headers(self, headers: Any) -> None:
        self.extra_headers = headers

    def clear_cookies(self) -> None:
        self.cookies_cleared = True


class FakePage:
    """A duck-typed Playwright sync page that records all calls.

    Exposes ``url`` as a property (like Playwright sync) reflecting the last goto;
    a submit ``click`` advances it to ``post_submit_url`` when set, simulating the
    post-login redirect so the ``submitted`` summary flag can be exercised.
    """

    def __init__(self) -> None:
        self.context = FakeContext()
        self.calls: List[Any] = []
        self._url = ""
        self.post_submit_url: Any = None
        self.html = ""

    @property
    def url(self) -> str:
        return self._url

    def content(self) -> str:
        return self.html

    def goto(self, url: str) -> None:
        self.calls.append(("goto", url))
        self._url = url

    def evaluate(self, script: str, arg: Any) -> None:
        self.calls.append(("evaluate", script, arg))

    def fill(self, selector: str, value: str) -> None:
        self.calls.append(("fill", selector, value))

    def click(self, selector: str) -> None:
        self.calls.append(("click", selector))
        if self.post_submit_url is not None:
            self._url = self.post_submit_url


def _assert_no_secret(summary: Dict[str, Any], secret: str) -> None:
    """The summary (recursively) must not contain the secret value anywhere."""
    import json as _json
    assert secret not in _json.dumps(summary)


def _make_plan_client(plan: Dict[str, Any]) -> AgentAuthClient:
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/v1/vault/credentials/{cid}/browser-login"
        # browser_login is the SAFE path: it must NOT request the raw endpoint.
        assert request.url.params.get("raw") is None
        return ok(plan)

    return AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))


def test_browser_login_cookie_mode_applies_and_summary_has_no_secret():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "cookie", "target": "github.com", "url": "https://github.com/home",
            "cookies": [{"name": "sid", "value": "SUPERSECRET", "path": "/"},
                        {"name": "csrf", "value": "TOKEN2", "path": "/"}]}
    page = FakePage()
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    assert page.context.added_cookies == plan["cookies"]
    assert ("goto", "https://github.com/home") in page.calls
    assert summary == {"mode": "cookie", "target": "github.com",
                       "url": "https://github.com/home",
                       "authenticated": True,
                       "cookie_names": ["sid", "csrf"]}
    _assert_no_secret(summary, "SUPERSECRET")
    _assert_no_secret(summary, "TOKEN2")


def test_browser_login_header_mode_applies_and_summary_has_no_secret():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "header", "target": "api.x.com", "url": "https://api.x.com/",
            "headers": {"Authorization": "Bearer SECRETVAL", "X-Key": "K2"}}
    page = FakePage()
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    assert page.context.extra_headers == plan["headers"]
    assert ("goto", "https://api.x.com/") in page.calls
    assert summary == {"mode": "header", "target": "api.x.com",
                       "url": "https://api.x.com/",
                       "authenticated": True,
                       "header_names": ["Authorization", "X-Key"]}
    _assert_no_secret(summary, "SECRETVAL")
    _assert_no_secret(summary, "K2")


def test_browser_login_local_storage_mode_applies_and_summary_has_no_secret():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "localStorage", "target": "app.x.com",
            "origin": "https://app.x.com", "url": "https://app.x.com/",
            "items": {"token": "LSSECRET", "rt": "REFRESHSECRET"}}
    page = FakePage()
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    # goto must happen before evaluate.
    assert page.calls[0] == ("goto", "https://app.x.com/")
    kind, script, arg = page.calls[1]
    assert kind == "evaluate"
    assert "localStorage.setItem" in script
    assert arg == plan["items"]
    assert summary == {"mode": "localStorage", "target": "app.x.com",
                       "url": "https://app.x.com/",
                       "authenticated": True,
                       "storage_keys": ["token", "rt"]}
    _assert_no_secret(summary, "LSSECRET")
    _assert_no_secret(summary, "REFRESHSECRET")


def test_browser_login_form_mode_applies_and_summary_has_no_secret():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "login.x.com", "url": "https://login.x.com/",
            "actions": [
                {"type": "goto", "url": "https://login.x.com/signin"},
                {"type": "fill", "selector": "#user", "value": "alice"},
                {"type": "fill", "selector": "#pass", "value": "PWSECRET"},
                {"type": "click", "selector": "#submit"},
            ],
            "successUrlIncludes": "/dashboard"}
    page = FakePage()
    # Simulate the post-login redirect to the dashboard after the submit click.
    page.post_submit_url = "https://login.x.com/dashboard"
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    assert page.calls == [
        ("goto", "https://login.x.com/signin"),
        ("fill", "#user", "alice"),
        ("fill", "#pass", "PWSECRET"),
        ("click", "#submit"),
    ]
    # filled_fields is a COUNT (matches the TS summary contract), and `submitted`
    # is present only because the plan carries successUrlIncludes and the landing
    # URL contains it.
    assert summary == {"mode": "form", "target": "login.x.com",
                       "url": "https://login.x.com/",
                       "authenticated": True,
                       "filled_fields": 2,
                       "submitted": True}
    _assert_no_secret(summary, "PWSECRET")
    _assert_no_secret(summary, "alice")


def test_browser_login_form_detects_mfa_by_url(monkeypatch):
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "site.x.com", "url": "https://site.x.com/login",
            "actions": [
                {"type": "fill", "selector": "#user", "value": "alice"},
                {"type": "fill", "selector": "#pass", "value": "PWSECRET"},
                {"type": "click", "selector": "#submit"},
            ],
            "successUrlIncludes": "/dashboard",
            "mfa": {"kind": "totp", "channelHint": "code from your authenticator app"}}
    page = FakePage()
    page.post_submit_url = "https://site.x.com/mfa/challenge"
    page.html = "<form><input type='password'></form>"
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    assert summary["authenticated"] is False
    assert summary["mfa"]["kind"] == "totp"
    assert summary["mfa"]["promptText"] == "code from your authenticator app"
    assert isinstance(summary["mfa"]["challengeId"], str)
    assert isinstance(summary["mfa"]["detectedAt"], str)
    _assert_no_secret(summary, "PWSECRET")
    _assert_no_secret(summary, "alice")


def test_browser_login_form_detects_mfa_by_text_and_input():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "site.x.com", "url": "https://site.x.com/login",
            "actions": [
                {"type": "fill", "selector": "#pass", "value": "PWSECRET"},
                {"type": "click", "selector": "#go"},
            ],
            "successUrlIncludes": "/home"}
    page = FakePage()
    page.post_submit_url = "https://site.x.com/step2"
    page.html = ("<h1>Verification code</h1><p>Enter the 6-digit code sent to "
                 "***1234</p><input autocomplete='one-time-code'>")
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    assert summary["authenticated"] is False
    assert summary["mfa"]["kind"] == "otp"  # default when spec omits kind
    assert "code" in summary["mfa"]["promptText"].lower()


def test_browser_login_masks_long_digit_runs_in_prompt_text():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "site.x.com", "url": "https://site.x.com/login",
            "actions": [{"type": "click", "selector": "#go"}],
            "successUrlIncludes": "/home"}
    page = FakePage()
    page.post_submit_url = "https://site.x.com/step2"
    # A long digit run (account number) is scraped next to the keyword.
    page.html = ("<h1>Verification code</h1><p>Enter the code for account 998812345 "
                 "sent to your authenticator</p><input autocomplete='one-time-code'>")
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    prompt = summary["mfa"]["promptText"]
    # 4+ digit runs are masked; the keyword survives so the prompt stays useful.
    assert not re.search(r"\d{4,}", prompt)
    assert "••••" in prompt
    assert "code" in prompt.lower()


def test_browser_login_form_success_url_is_authenticated_no_mfa():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "site.x.com", "url": "https://site.x.com/login",
            "actions": [
                {"type": "fill", "selector": "#pass", "value": "PWSECRET"},
                {"type": "click", "selector": "#go"},
            ],
            "successUrlIncludes": "/dashboard"}
    page = FakePage()
    page.post_submit_url = "https://site.x.com/dashboard"
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    assert summary["authenticated"] is True
    assert "mfa" not in summary
    assert summary["submitted"] is True


def test_browser_login_form_mode_omits_submitted_without_success_hint():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "login.x.com", "url": "https://login.x.com/",
            "actions": [
                {"type": "fill", "selector": "#pass", "value": "PWSECRET"},
                {"type": "click", "selector": "#submit"},
            ]}
    page = FakePage()
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)

    # No successUrlIncludes in the plan -> `submitted` key is omitted entirely.
    assert "submitted" not in summary
    assert summary["filled_fields"] == 1


_MFA_CHALLENGE = {"kind": "totp", "promptText": "enter code", "detectedAt": "n", "challengeId": "ch1"}


def test_resolve_mfa_full_flow_injects_code():
    cid = "11111111-1111-4111-8111-111111111111"
    state = {"poll": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/mfa/request"):
            return ok({"requestId": "req-1", "status": "pending"})
        if request.method == "GET" and "/mfa/request/req-1" in request.url.path:
            state["poll"] += 1
            if state["poll"] == 1:
                return ok({"status": "pending"})
            return ok({"status": "approved", "code": "123456",
                       "by": "owner@example.com", "at": "t"})
        raise AssertionError(request.url.path)

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    res = client.resolve_mfa(page, cid, _MFA_CHALLENGE, input_selector="#otp",
                             submit_selector="#go", sleep=lambda *_: None)

    assert res["resolved"] is True
    assert res["status"] == "approved"
    assert res["by"] == "owner@example.com"
    assert ("fill", "#otp", "123456") in page.calls  # code injected into the DOM
    assert ("click", "#go") in page.calls
    _assert_no_secret(res, "123456")  # ...but never in the resolution


def test_resolve_mfa_denied_does_not_inject():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return ok({"requestId": "r", "status": "pending"})
        return ok({"status": "denied"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    res = client.resolve_mfa(page, cid, _MFA_CHALLENGE, input_selector="#otp", sleep=lambda *_: None)
    assert res["resolved"] is False
    assert res["status"] == "denied"
    assert not any(c[0] == "fill" for c in page.calls)


def test_resolve_mfa_approved_without_selector_is_not_resolved():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return ok({"requestId": "r", "status": "pending"})
        return ok({"status": "approved", "code": "123456", "by": "o@e.com", "at": "t"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    # No input_selector kwarg and the challenge carries none -> code can't be applied.
    res = client.resolve_mfa(page, cid, _MFA_CHALLENGE, sleep=lambda *_: None)
    assert res["resolved"] is False
    assert res["status"] == "approved"
    assert not any(c[0] == "fill" for c in page.calls)


def test_resolve_mfa_falls_back_to_challenge_selector():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return ok({"requestId": "r", "status": "pending"})
        return ok({"status": "approved", "code": "123456", "by": "o@e.com", "at": "t"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    challenge = {**_MFA_CHALLENGE, "inputSelector": "#otp", "submitSelector": "#verify"}
    res = client.resolve_mfa(page, cid, challenge, sleep=lambda *_: None)
    assert res["resolved"] is True
    assert ("fill", "#otp", "123456") in page.calls


def test_resolve_mfa_410_is_expired():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return ok({"requestId": "r", "status": "pending"})
        return httpx.Response(410, json={"error": {"code": "expired", "message": "gone"}})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    res = client.resolve_mfa(page, cid, _MFA_CHALLENGE, input_selector="#otp", sleep=lambda *_: None)
    assert res["resolved"] is False
    assert res["status"] == "expired"


def test_form_refuses_navigation_outside_allowed_domains():
    from agentauth.browser import apply_browser_login

    plan = {"mode": "form", "target": "app.example.com", "url": "https://app.example.com/login",
            "actions": [{"type": "goto", "url": "https://evil.example.org/login"}],
            "allowedDomains": ["app.example.com"]}
    with pytest.raises(ValueError, match="allowedDomains"):
        apply_browser_login(FakePage(), plan)


def test_form_allows_subdomain_within_allowed_domains():
    from agentauth.browser import apply_browser_login

    plan = {"mode": "form", "target": "example.com", "url": "https://app.example.com/login",
            "actions": [
                {"type": "goto", "url": "https://app.example.com/login"},
                {"type": "fill", "selector": "#p", "value": "SECRET"},
            ],
            "allowedDomains": ["*.example.com"]}
    summary = apply_browser_login(FakePage(), plan)
    assert summary["filled_fields"] == 1
    assert summary["authenticated"] is True


def test_form_refuses_fill_after_click_redirects_off_list():
    from agentauth.browser import apply_browser_login

    plan = {"mode": "form", "target": "app.example.com", "url": "https://app.example.com/login",
            "actions": [
                {"type": "goto", "url": "https://app.example.com/login"},  # on-list
                {"type": "click", "selector": "#go"},                       # redirects off-list
                {"type": "fill", "selector": "#otp", "value": "SECRET"},    # must NOT be typed
            ],
            "allowedDomains": ["app.example.com"]}
    page = FakePage()
    page.post_submit_url = "https://evil.example.org/landing"
    with pytest.raises(ValueError, match="allowedDomains"):
        apply_browser_login(page, plan)
    assert ("fill", "#otp", "SECRET") not in page.calls  # secret never typed off-list


def test_cookie_mode_enforces_allowed_domains():
    from agentauth.browser import apply_browser_login

    plan = {"mode": "cookie", "target": "app.example.com", "url": "https://evil.example.org/",
            "cookies": [{"name": "s", "value": "SECRET", "path": "/"}],
            "allowedDomains": ["app.example.com"]}
    page = FakePage()
    with pytest.raises(ValueError, match="allowedDomains"):
        apply_browser_login(page, plan)
    # The allowlist is checked BEFORE any secret state is planted: an off-list url
    # must leave no cookies in the context and no navigation.
    assert page.context.added_cookies is None
    assert ("goto", "https://evil.example.org/") not in page.calls


def test_local_storage_mode_enforces_allowed_domains():
    from agentauth.browser import apply_browser_login

    plan = {"mode": "localStorage", "target": "app.example.com",
            "origin": "https://app.example.com", "url": "https://evil.example.org/",
            "items": {"t": "SECRET"}, "allowedDomains": ["app.example.com"]}
    with pytest.raises(ValueError, match="allowedDomains"):
        apply_browser_login(FakePage(), plan)


def test_header_mode_enforces_allowed_domains():
    from agentauth.browser import apply_browser_login

    plan = {"mode": "header", "target": "app.example.com", "url": "https://evil.example.org/",
            "headers": {"Authorization": "Bearer SECRET"}, "allowedDomains": ["app.example.com"]}
    page = FakePage()
    with pytest.raises(ValueError, match="allowedDomains"):
        apply_browser_login(page, plan)
    # The allowlist is checked BEFORE the context-wide Authorization header is planted:
    # an off-list url must leave no extra headers and trigger no navigation.
    assert page.context.extra_headers is None
    assert ("goto", "https://evil.example.org/") not in page.calls


def test_resolve_mfa_refuses_off_list_code_injection():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return ok({"requestId": "r", "status": "pending"})
        return ok({"status": "approved", "code": "123456", "by": "o@e.com", "at": "t"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    page.goto("https://evil.example.org/landing")  # browser drifted off-list
    challenge = {**_MFA_CHALLENGE, "allowedDomains": ["app.example.com"]}
    with pytest.raises(ValueError, match="allowedDomains"):
        client.resolve_mfa(page, cid, challenge, input_selector="#otp", sleep=lambda *_: None)
    assert not any(c[0] == "fill" for c in page.calls)  # OTP never typed off-list


def test_detect_mfa_does_not_scrape_off_list_page_text():
    cid = "11111111-1111-4111-8111-111111111111"
    plan = {"mode": "form", "target": "app.example.com", "url": "https://app.example.com/login",
            "actions": [
                {"type": "goto", "url": "https://app.example.com/login"},  # on-list
                {"type": "click", "selector": "#go"},                       # redirects off-list
            ],
            "allowedDomains": ["app.example.com"]}
    page = FakePage()
    page.post_submit_url = "https://evil.example.org/landing"
    page.html = "<h1>Verification code</h1><p>PHISH-TEXT enter the one-time code</p>"
    client = _make_plan_client(plan)
    summary = client.browser_login(page, cid)
    assert "mfa" in summary
    # Off-list HTML must NOT be scraped into promptText; fall back to the static string.
    assert summary["mfa"]["promptText"] == "Multi-factor authentication required"
    assert "PHISH-TEXT" not in summary["mfa"]["promptText"]
    assert summary["mfa"]["allowedDomains"] == ["app.example.com"]


def test_resolve_mfa_revoked_forces_logout():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return ok({"requestId": "r", "status": "pending"})
        return ok({"status": "revoked"})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    res = client.resolve_mfa(page, cid, _MFA_CHALLENGE, input_selector="#otp", sleep=lambda *_: None)
    assert res["resolved"] is False
    assert res["status"] == "revoked"
    # A revoked poll must force-logout so the session can't outlive the revoked agent.
    assert page.context.cookies_cleared is True
    assert ("goto", "about:blank") in page.calls


def test_browser_login_force_logout_on_revoked_401():
    cid = "11111111-1111-4111-8111-111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"code": "unauthorized", "message": "revoked"}})

    client = AgentAuthClient(BASE, "aa_key.secret", transport=make_transport(handler))
    page = FakePage()
    with pytest.raises(AgentAuthError) as exc:
        client.browser_login(page, cid)
    assert exc.value.status == 401
    assert page.context.cookies_cleared is True
    assert ("goto", "about:blank") in page.calls


def test_apply_browser_login_unknown_mode_raises():
    from agentauth.browser import apply_browser_login

    with pytest.raises(ValueError):
        apply_browser_login(FakePage(), {"mode": "telepathy"})


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

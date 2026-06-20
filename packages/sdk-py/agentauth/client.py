"""Synchronous HTTP clients for the AgentAuth API.

Two clients are provided, mirroring the two authentication surfaces of the API:

* :class:`HumanClient` — authenticated with a human session JWT (Bearer token).
  Used for the management plane: registering principals, opening passports,
  depositing credentials (with optional usage policy), issuing/revoking agents,
  binding mTLS client certs (:meth:`HumanClient.bind_agent_mtls`), starting
  OAuth flows (:meth:`HumanClient.start_oauth`), reviewing the approvals queue
  (``list_approvals`` / ``approve_request`` / ``deny_request``), and reading the
  audit log.

* :class:`AgentAuthClient` — authenticated with an agent API key
  (``aa_<uuid>.<secret>``). Used for the data plane: an agent discovering and
  using the credentials it has been granted — ``use_credential`` (unseal),
  ``proxy`` (server-side request injection), and ``browser_login`` /
  ``get_browser_login_plan`` (drive a Playwright page into a logged-in session).

Both are thin wrappers over :mod:`httpx`. Every non-2xx response is translated
into an :class:`~agentauth.errors.AgentAuthError`. The clients are usable as
context managers so the underlying connection pool is closed deterministically.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Union

import httpx

from .errors import AgentAuthError, ApprovalPendingError

# Public API base path. All resource endpoints live under /v1.
_API_PREFIX = "/v1"

# Credential ids are UUIDs. We resolve id-vs-target up front (like the TS SDKs)
# rather than POSTing a target string to /:id/* — the server's :id is a Postgres
# uuid column, so a non-uuid id is not a clean 404 to fall back on.
# Match the TS SDKs' RFC-shaped pattern exactly (version nibble 1-5, variant
# nibble 8-b) so all three clients agree on which strings are ids vs targets. A
# looser pattern would route e.g. the nil UUID to /:id here but treat it as a
# target in the TS clients — divergent behaviour for the same argument.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def _target_host(target: str) -> str:
    """Reduce a target to its bare host, mirroring the server's targetHost (strip
    scheme/path/port/IPv6-brackets/trailing-dot, lowercase). The server authorizes
    and lists by host, so by-target resolution must compare hosts."""
    h = _SCHEME_RE.sub("", target.strip())
    slash = h.find("/")
    if slash >= 0:
        h = h[:slash]
    if h.startswith("["):
        end = h.find("]")
        if end >= 0:
            h = h[1:end]
    else:
        colon = h.find(":")
        if colon >= 0:
            h = h[:colon]
    return h.rstrip(".").lower()

# Default per-request timeout (seconds). The vault deliberately fails closed and
# can return 503 quickly, so a modest default is fine; callers may override.
_DEFAULT_TIMEOUT = 30.0


def _force_logout(page: Any) -> None:
    """Force-logout a page after the agent is revoked: clear context cookies and
    navigate to a blank page so the session can't outlive the revoked agent.
    Best-effort and never raises."""
    try:
        ctx = getattr(page, "context", None)
        clear = getattr(ctx, "clear_cookies", None) if ctx is not None else None
        if callable(clear):
            clear()
    except Exception:  # noqa: BLE001
        pass
    try:
        page.goto("about:blank")
    except Exception:  # noqa: BLE001
        pass


JSON = Dict[str, Any]
Page = Dict[str, Any]


class _BaseClient:
    """Shared transport logic for the human and agent clients.

    Handles base-url normalisation, the Authorization header, JSON
    (de)serialisation, and the single error-envelope -> exception mapping.
    """

    def __init__(
        self,
        base_url: str,
        *,
        auth_header: Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        # Strip a trailing slash so we can concatenate paths unambiguously.
        self._base_url = base_url.rstrip("/")
        if http_client is not None:
            # Caller-supplied client (e.g. preconfigured proxies); we don't own it.
            self._http = http_client
            self._owns_http = False
        else:
            headers: Dict[str, str] = {"accept": "application/json"}
            if auth_header:
                headers["authorization"] = auth_header
            self._http = httpx.Client(
                base_url=self._base_url,
                headers=headers,
                timeout=timeout,
                transport=transport,
            )
            self._owns_http = True

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP connection pool (if we own it)."""
        if self._owns_http:
            self._http.close()

    def __enter__(self):  # noqa: D401 - context manager protocol
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- low-level request -------------------------------------------------

    def _set_auth(self, auth_header: str) -> None:
        """Update the Authorization header in place (used after login)."""
        self._http.headers["authorization"] = auth_header

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        """Perform a request and return decoded JSON, or raise AgentAuthError."""
        url = f"{_API_PREFIX}{path}"
        try:
            resp = self._http.request(method, url, json=json, params=params)
        except httpx.HTTPError as exc:  # network/timeout/transport failures
            # Surface transport failures through the same exception type so
            # callers have one thing to catch. Status 0 == "never reached".
            raise AgentAuthError(
                status=0,
                code="network_error",
                message=str(exc) or "request failed before a response was received",
            ) from exc

        if resp.is_success:
            # 202 is only ever the approval-pending response (body has a
            # requestId, not a real result) — surface it as a typed error so a
            # caller can't mistake it for an unsealed credential.
            if resp.status_code == 202:
                body = resp.json() if resp.content else {}
                raise ApprovalPendingError(
                    request_id=body.get("requestId"),
                    message=body.get("message", "credential use is awaiting human approval"),
                )
            if not resp.content:
                return None
            return resp.json()

        raise self._to_error(resp)

    @staticmethod
    def _to_error(resp: httpx.Response) -> AgentAuthError:
        """Translate a non-2xx response into a structured AgentAuthError.

        The server's canonical shape is ``{"error": {...}}`` but we degrade
        gracefully for proxies / unexpected bodies (e.g. an HTML 502).
        """
        code = "http_error"
        message = resp.reason_phrase or f"HTTP {resp.status_code}"
        request_id: Optional[str] = None
        details: Any = None

        try:
            body = resp.json()
        except ValueError:
            body = None

        if isinstance(body, dict):
            envelope = body.get("error")
            if isinstance(envelope, dict):
                code = envelope.get("code", code)
                message = envelope.get("message", message)
                request_id = envelope.get("requestId")
                details = envelope.get("details")

        # Fall back to the standard header if the envelope omitted the id.
        if request_id is None:
            request_id = resp.headers.get("x-request-id")

        return AgentAuthError(
            status=resp.status_code,
            code=code,
            message=message,
            request_id=request_id,
            details=details,
        )


class HumanClient(_BaseClient):
    """Management-plane client authenticated with a human session JWT.

    Example::

        client = HumanClient("https://api.agentauth.dev")
        client.login(email="me@example.com", password="...")
        passport = client.create_passport("work")
        client.deposit_credential(passport["id"], target="github.com",
                                   label="GH", type="api_key", secret="ghp_x")
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(
            base_url,
            auth_header=f"Bearer {token}" if token else None,
            timeout=timeout,
            transport=transport,
            http_client=http_client,
        )
        self.token = token

    # -- auth --------------------------------------------------------------

    def register(self, email: str, password: str) -> JSON:
        """Create a new principal (human account). Returns ``{id, email}``.

        Does not log in; call :meth:`login` afterwards to obtain a token.
        """
        return self._request(
            "POST", "/principals", json={"email": email, "password": password}
        )

    def login(self, email: str, password: str) -> JSON:
        """Exchange credentials for a session token and store it on the client.

        Returns the raw login payload ``{token, tokenType, expiresAt}`` and
        sets the Authorization header so subsequent calls are authenticated.
        """
        data = self._request(
            "POST", "/auth/login", json={"email": email, "password": password}
        )
        self.token = data["token"]
        token_type = data.get("tokenType") or "Bearer"
        self._set_auth(f"{token_type} {self.token}")
        return data

    def logout(self) -> JSON:
        """Revoke the current session (adds the jti to the denylist)."""
        data = self._request("POST", "/auth/logout")
        # Clear local auth state; the token is now dead server-side.
        self.token = None
        self._http.headers.pop("authorization", None)
        return data

    # -- passports ---------------------------------------------------------

    def create_passport(self, name: str) -> JSON:
        """Open a new passport. Returns ``{id, name, createdAt}``."""
        return self._request("POST", "/passports", json={"name": name})

    def list_passports(self, *, limit: Optional[int] = None,
                       offset: Optional[int] = None) -> Page:
        """List passports as a page ``{items, pagination}``."""
        return self._request("GET", "/passports", params=_page_params(limit, offset))

    # -- credentials (deposit) --------------------------------------------

    def deposit_credential(
        self,
        passport_id: str,
        *,
        target: str,
        label: str,
        type: str,  # noqa: A002 - mirrors the API field name
        secret: str,
        metadata: Optional[Mapping[str, Any]] = None,
        expires_at: Optional[str] = None,
        injection: Optional[Mapping[str, Any]] = None,
        max_uses: Optional[int] = None,
        allowed_from: Optional[str] = None,
        allowed_until: Optional[str] = None,
        require_approval: Optional[bool] = None,
    ) -> JSON:
        """Seal a credential into a passport.

        ``type`` must be one of ``password|oauth_token|cookie|api_key``.
        ``expires_at`` is an ISO-8601 timestamp string if provided.

        ``injection`` optionally describes how the secret is injected when the
        credential is used in **proxy mode**. It mirrors the server contract::

            {"mode": "bearer"}
            {"mode": "basic"}
            {"mode": "cookie"}
            {"mode": "header", "name": "X-Api-Key", "prefix": "Token "}
            {"mode": "query",  "name": "api_key"}

        Defaults server-side to ``bearer`` (or ``cookie`` for type ``cookie``).

        Optional usage **policy** (all server-enforced; forwarded only when set):

        * ``max_uses`` — cap the number of uses (positive int).
        * ``allowed_from`` / ``allowed_until`` — ISO-8601 time window in which the
          credential may be used.
        * ``require_approval`` — if true, each use queues a human approval request
          (the agent gets ``202`` -> :class:`ApprovalPendingError`).

        Returns the credential metadata (never the secret).
        """
        body: Dict[str, Any] = {
            "target": target,
            "label": label,
            "type": type,
            "secret": secret,
        }
        if metadata is not None:
            body["metadata"] = metadata
        if expires_at is not None:
            body["expiresAt"] = expires_at
        if injection is not None:
            body["injection"] = dict(injection)
        if max_uses is not None:
            body["maxUses"] = max_uses
        if allowed_from is not None:
            body["allowedFrom"] = allowed_from
        if allowed_until is not None:
            body["allowedUntil"] = allowed_until
        if require_approval is not None:
            body["requireApproval"] = require_approval
        return self._request(
            "POST", f"/passports/{passport_id}/credentials", json=body
        )

    def list_credentials(self, passport_id: str, *, limit: Optional[int] = None,
                         offset: Optional[int] = None) -> Page:
        """List the credentials in a passport (metadata only, no secrets)."""
        return self._request(
            "GET",
            f"/passports/{passport_id}/credentials",
            params=_page_params(limit, offset),
        )

    # -- agents ------------------------------------------------------------

    def issue_agent(
        self,
        *,
        passport_id: str,
        name: str,
        scopes: List[str],
        expires_at: Optional[str] = None,
    ) -> JSON:
        """Mint a scoped agent API key bound to a passport.

        Returns ``{id, name, scopes, apiKey, warning}``. The ``apiKey`` is shown
        exactly once — capture it from the return value.
        """
        body: Dict[str, Any] = {
            "passportId": passport_id,
            "name": name,
            "scopes": list(scopes),
        }
        if expires_at is not None:
            body["expiresAt"] = expires_at
        return self._request("POST", "/agents", json=body)

    def list_agents(self, *, limit: Optional[int] = None,
                    offset: Optional[int] = None) -> Page:
        """List agents bound to your principal."""
        return self._request("GET", "/agents", params=_page_params(limit, offset))

    def revoke_agent(self, agent_id: str) -> JSON:
        """Revoke an agent immediately (fail-closed). Returns ``{id, revoked}``."""
        return self._request("POST", f"/agents/{agent_id}/revoke")

    def bind_agent_mtls(
        self,
        agent_id: str,
        *,
        cert_pem: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> JSON:
        """Bind an mTLS client certificate to one of your agents.

        Provide **either** a PEM cert (``cert_pem`` — the SHA-256 fingerprint is
        derived server-side) **or** a pre-computed ``fingerprint``. The agent may
        then authenticate with that client cert (by fingerprint) as an alternative
        to its bearer API key. The binding is an idempotent overwrite.

        Returns ``{id, certFingerprint}``.

        Raises:
            AgentAuthError: ``400`` (neither/invalid input), ``404`` (agent not
                yours), ``409`` (fingerprint already bound to another agent).
        """
        body: Dict[str, Any] = {}
        if cert_pem is not None:
            body["certPem"] = cert_pem
        if fingerprint is not None:
            body["fingerprint"] = fingerprint
        return self._request("POST", f"/agents/{agent_id}/mtls", json=body)

    # -- audit -------------------------------------------------------------

    def list_audit(self, *, limit: Optional[int] = None,
                   offset: Optional[int] = None) -> Page:
        """Read the audit event log as a page."""
        return self._request("GET", "/audit", params=_page_params(limit, offset))

    def verify_audit(self) -> JSON:
        """Verify the audit hash-chain. Returns ``{ok}`` (the boolean integrity
        signal only; the global event count / broken sequence are not exposed)."""
        return self._request("GET", "/audit/verify")

    # -- approvals ---------------------------------------------------------

    def list_approvals(self, *, limit: Optional[int] = None,
                       offset: Optional[int] = None) -> Page:
        """List pending approval requests across the passports you own."""
        return self._request("GET", "/approvals", params=_page_params(limit, offset))

    def approve_request(self, request_id: str) -> JSON:
        """Approve a pending request. Returns the updated approval request."""
        return self._request("POST", f"/approvals/{request_id}/approve")

    def deny_request(self, request_id: str) -> JSON:
        """Deny a pending request. Returns the updated approval request."""
        return self._request("POST", f"/approvals/{request_id}/deny")

    # -- oauth -------------------------------------------------------------

    def start_oauth(
        self,
        passport_id: str,
        provider: str,
        *,
        target: Optional[str] = None,
        label: Optional[str] = None,
    ) -> JSON:
        """Begin an OAuth authorization-code flow for a passport.

        Mints PKCE + state server-side and returns ``{authorizeUrl, state}``.
        Send the human's browser to ``authorizeUrl``; the provider redirects back
        to the server callback, which seals the tokens as an ``oauth_token``
        credential the agent can reuse (with transparent refresh).

        ``target`` overrides where the credential will be used (defaults to the
        provider name, server-side); ``label`` overrides the credential label.

        Raises:
            AgentAuthError: ``404`` (passport not yours / unknown provider),
                ``500`` (``oauth_misconfigured``), ``400`` (invalid body).
        """
        body: Dict[str, Any] = {}
        if target is not None:
            body["target"] = target
        if label is not None:
            body["label"] = label
        return self._request(
            "POST", f"/passports/{passport_id}/oauth/{provider}/start", json=body
        )


class AgentAuthClient(_BaseClient):
    """Data-plane client authenticated with an agent API key.

    This is the one-liner the agent uses at runtime::

        client = AgentAuthClient("https://api.agentauth.dev", "aa_...secret")
        cred = client.use_credential("github.com")
        token = cred["secret"]
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required for AgentAuthClient")
        super().__init__(
            base_url,
            auth_header=f"Bearer {api_key}",
            timeout=timeout,
            transport=transport,
            http_client=http_client,
        )
        self.api_key = api_key

    def list_credentials(self, *, limit: Optional[int] = None,
                         offset: Optional[int] = None) -> Page:
        """Discover the credentials this agent is allowed to see (no secrets)."""
        return self._request(
            "GET", "/vault/credentials", params=_page_params(limit, offset)
        )

    def use_credential(self, id_or_target: str, *, limit: int = 200) -> JSON:
        """Unseal and return a credential, by id **or** by target host.

        If ``id_or_target`` is a credential id (UUID) it is used directly.
        Otherwise it is treated as a ``target`` and resolved against the agent's
        visible credentials (the data plane has no target-lookup endpoint, so
        resolution happens client-side).

        Returns ``{id, target, label, type, metadata, secret}``.

        Raises:
            AgentAuthError: ``not_found`` (404) if no credential matches the
                target; or whatever the server returns for an id-based use.
        """
        cred_id = self._resolve_id_or_target(id_or_target, limit=limit)
        return self._use_by_id(cred_id)

    def proxy(
        self,
        id_or_target: str,
        *,
        method: str = "GET",
        path: str = "/",
        query: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[str] = None,
        limit: int = 200,
    ) -> JSON:
        """Make a downstream request **through the vault**, by id or target.

        AgentAuth performs the request server-side against the credential's
        pinned target and injects the secret — the raw secret never appears in
        the response. The agent only controls ``method``/``path``/``query``/
        ``headers``/``body``; the host is fixed to the credential's target.

        ``id_or_target`` is resolved exactly like :meth:`use_credential`: a UUID
        is used as the credential **id** directly; anything else is resolved as a
        **target** against the agent's visible credentials.

        Returns the downstream response ``{status, headers, body}`` (secret
        redacted). ``path`` must start with ``"/"``.

        Raises:
            AgentAuthError: for the proxy-mode error contract — ``403`` (missing
                ``vault:proxy`` / target not scoped / forbidden_target), ``400``
                (invalid request/path), ``410`` (expired/window), ``429``
                (use_limit_reached), ``502`` (oauth_refresh_failed/upstream),
                ``504`` (timeout), ``500`` (``internal`` — the server failed to
                unseal the credential: corrupt/tampered ciphertext, a wrong/rotated
                key, or an oauth token whose sealed JSON can't be parsed); or
                ``404`` if the credential id does not exist / isn't visible, or no
                credential matches a target.
            ApprovalPendingError: ``202`` when human approval is required.
        """
        cred_id = self._resolve_id_or_target(id_or_target, limit=limit)
        return self._proxy_by_id(
            cred_id, method=method, path=path,
            query=query, headers=headers, body=body,
        )

    def get_browser_login_plan(self, id_or_target: str, *, limit: int = 200) -> JSON:
        """**The liability path.** Fetch the raw browser-login *plan* for a credential.

        The returned plan **carries the secret in plaintext to your process**. Treat
        it like a decrypted password: do not log it, do not pass it to an LLM, do not
        persist it. AgentAuth cannot enforce this once it leaves the server — the
        trust boundary moves to your process. **Prefer :meth:`browser_login`** (which
        applies the plan to a page and confines the secret) unless you have a concrete
        reason you cannot.

        Requires the **`vault:browser:raw`** scope (off by default) IN ADDITION to
        ``vault:use``; without it the call is ``403 missing_scope``. ``id_or_target``
        is resolved exactly like :meth:`use_credential`. The plan is keyed on ``mode``::

            cookie:       {"mode","target","url","cookies":[...]}
            header:       {"mode","target","url","headers":{...}}
            localStorage: {"mode","target","origin","url","items":{...}}
            form:         {"mode","target","url","actions":[...],"successUrlIncludes"?}

        Raises:
            AgentAuthError: for the standard error envelope (``403`` missing
                ``vault:browser:raw`` / ``vault:use`` / target not scoped, ``404``
                not found, ``410`` expired, ``422`` no/invalid browser spec, ``429``
                use-limit reached, ...).
            ApprovalPendingError: ``202`` when human approval is required.
        """
        cred_id = self._resolve_id_or_target(id_or_target, limit=limit)
        return self._browser_login_by_id(cred_id, raw=True)

    def browser_login(self, page: Any, id_or_target: str, *, limit: int = 200) -> JSON:
        """Log a Playwright **sync** ``page`` into a credential's target.

        The SAFE path: fetches the plan (NON-raw — needs only ``vault:use``, NOT
        ``vault:browser:raw``) and applies it to the duck-typed ``page`` (see
        :mod:`agentauth.browser`). Returns a **non-secret summary** ``{mode, target,
        url, ...names/counts}`` — never a cookie/header/storage/form value. The
        actual secret material is applied to the page and is not echoed back.

        ``page`` is duck-typed: only the methods the plan needs are called
        (``page.context.add_cookies`` / ``page.context.set_extra_http_headers`` /
        ``page.goto`` / ``page.evaluate`` / ``page.fill`` / ``page.click``), so
        Playwright is never imported by the SDK.

        Raises the same errors as :meth:`get_browser_login_plan`.
        """
        # Imported lazily so the SDK has no top-level dependency on this helper's
        # (duck-typed) Playwright assumptions; mirrors browser.py's import policy.
        from .browser import apply_browser_login

        # The SAFE path: fetch the plan NON-raw (vault:use only — no
        # vault:browser:raw needed), apply it to the page, and return only a
        # non-secret summary. The secret never leaves this method. A 401 means the
        # agent was revoked — force-logout the browser before surfacing it.
        cred_id = self._resolve_id_or_target(id_or_target, limit=limit)
        try:
            plan = self._browser_login_by_id(cred_id, raw=False)
        except AgentAuthError as exc:
            if exc.status == 401:
                _force_logout(page)
            raise
        return apply_browser_login(page, plan)

    def resolve_mfa(
        self,
        page: Any,
        id_or_target: str,
        challenge: Mapping[str, Any],
        *,
        input_selector: Optional[str] = None,
        submit_selector: Optional[str] = None,
        channel_hint: Optional[str] = None,
        timeout_s: float = 300.0,
        poll_interval_s: float = 2.0,
        sleep: Any = None,
        limit: int = 200,
    ) -> Dict[str, Any]:
        """Resolve a detected MFA ``challenge`` via the human approval queue.

        Opens a request, polls until a credential owner approves (or it is denied /
        expires / times out), and on approval injects the one-time code into the
        page and submits. **The code flows only into the browser DOM** — it is never
        placed in the returned resolution dict or logged. Returns
        ``{"resolved": bool, "status": "approved"|"denied"|"revoked"|"expired"|"timeout", "by"?, "at"?}``.
        """
        import time

        sleeper = sleep or time.sleep
        cred_id = self._resolve_id_or_target(id_or_target, limit=limit)
        body: Dict[str, Any] = {
            "challengeId": challenge["challengeId"],
            "kind": challenge["kind"],
            "promptText": challenge.get("promptText"),
        }
        if channel_hint is not None:
            body["channelHint"] = channel_hint
        try:
            opened = self._request("POST", f"/vault/credentials/{cred_id}/mfa/request", json=body)
        except AgentAuthError as exc:
            if exc.status == 401:  # agent revoked
                _force_logout(page)
            raise
        request_id = opened["requestId"]

        max_polls = max(1, int(timeout_s / poll_interval_s) + 1)
        for _ in range(max_polls):
            try:
                res = self._request(
                    "GET", f"/vault/credentials/{cred_id}/mfa/request/{request_id}"
                )
            except AgentAuthError as exc:
                if exc.status == 410:  # expired / already consumed
                    return {"resolved": False, "status": "expired"}
                if exc.status == 401:  # agent revoked mid-flow
                    _force_logout(page)
                raise
            status = res.get("status")
            if status == "denied":
                return {"resolved": False, "status": "denied"}
            if status == "revoked":
                return {"resolved": False, "status": "revoked"}
            if status == "approved":
                code = res.get("code")
                in_sel = input_selector or challenge.get("inputSelector")
                sub_sel = submit_selector or challenge.get("submitSelector")
                if code:
                    if not in_sel:
                        # Approved + code, but no selector to fill it — the form was
                        # NOT advanced. Report not-resolved (code consumed, unapplied).
                        return {"resolved": False, "status": "approved",
                                "by": res.get("by"), "at": res.get("at")}
                    page.fill(in_sel, code)
                    if sub_sel:
                        page.click(sub_sel)
                return {"resolved": True, "status": "approved", "by": res.get("by"), "at": res.get("at")}
            sleeper(poll_interval_s)
        return {"resolved": False, "status": "timeout"}

    # -- internals ---------------------------------------------------------

    def _resolve_id_or_target(self, id_or_target: str, *, limit: int) -> str:
        """Return a credential id for an id-or-target argument.

        A UUID is used directly; anything else is resolved as a target against
        the agent's visible credentials (the data plane has no target-lookup
        endpoint). Mirrors the TS SDKs — we never POST a target string to a
        uuid-typed ``:id`` route.
        """
        if _UUID_RE.match(id_or_target):
            return id_or_target
        cred_id = self._resolve_target(id_or_target, limit=limit)
        if cred_id is None:
            raise AgentAuthError(
                status=404,
                code="not_found",
                message=f"no credential found for target {id_or_target!r}",
            )
        return cred_id

    def _proxy_by_id(
        self,
        credential_id: str,
        *,
        method: str,
        path: str,
        query: Optional[Mapping[str, str]],
        headers: Optional[Mapping[str, str]],
        body: Optional[str],
    ) -> JSON:
        payload: Dict[str, Any] = {"method": method, "path": path}
        if query is not None:
            payload["query"] = dict(query)
        if headers is not None:
            payload["headers"] = dict(headers)
        if body is not None:
            payload["body"] = body
        return self._request(
            "POST", f"/vault/credentials/{credential_id}/proxy", json=payload
        )

    def _use_by_id(self, credential_id: str) -> JSON:
        return self._request(
            "POST", f"/vault/credentials/{credential_id}/use"
        )

    def _browser_login_by_id(self, credential_id: str, *, raw: bool = False) -> JSON:
        # raw=True hits the liability endpoint (?raw=true), gated by the
        # vault:browser:raw scope; raw=False is the SDK-applied path (vault:use).
        params = {"raw": "true"} if raw else None
        return self._request(
            "POST", f"/vault/credentials/{credential_id}/browser-login", params=params
        )

    def _resolve_target(self, target: str, *, limit: int) -> Optional[str]:
        """Return the id of the first visible credential matching ``target``.

        Pages through the agent's credential listing. Most agents are scoped to
        a handful of targets, so this is cheap in practice.
        """
        # Match on bare host (like the server's allowsTarget), so URL/host:port targets resolve.
        want = _target_host(target)
        offset = 0
        while True:
            page = self.list_credentials(limit=limit, offset=offset)
            items: List[JSON] = page.get("items", [])
            for item in items:
                if _target_host(str(item.get("target", ""))) == want:
                    return item.get("id")
            pagination = page.get("pagination", {})
            returned = pagination.get("returned", len(items))
            total = pagination.get("total")
            offset += returned
            # Stop when we've drained the result set or made no progress.
            if returned == 0:
                return None
            if total is not None and offset >= total:
                return None


def _page_params(limit: Optional[int], offset: Optional[int]) -> Dict[str, Any]:
    """Build a params dict, omitting unset pagination values."""
    params: Dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    return params


__all__ = [
    "AgentAuthClient",
    "HumanClient",
    "AgentAuthError",
]

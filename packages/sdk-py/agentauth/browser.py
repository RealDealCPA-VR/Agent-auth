"""Apply a browser-login plan to a Playwright page.

The data-plane endpoint ``POST /v1/vault/credentials/:id/browser-login`` returns
a *plan* that carries secret material (cookies / header values / localStorage
values / form field values) describing how to put a duck-typed Playwright **sync**
``page`` into a logged-in state — without the agent ever pasting the secret by
hand.

This module is deliberately import-light: it never imports ``playwright`` at the
top level. The page (and its ``page.context``) is duck-typed, so the logic is
trivially testable against a fake page object that records calls, and the SDK has
no hard dependency on Playwright.

Every entry point returns a **non-secret summary**: only the mode/target/url and
names/counts of what was applied — never a cookie/header/storage value.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlparse


def _url_host(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower().rstrip(".")
    except Exception:  # noqa: BLE001 - any parse failure -> empty host
        return ""


def _host_allowed(host: str, allowed: List[str]) -> bool:
    for raw in allowed:
        p = raw.strip().lower()
        if p == "*":
            return True
        if p.startswith("*."):
            suffix = p[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif host == p:
            return True
    return False


def _assert_nav_allowed(url: str, allow: Any) -> None:
    """Refuse navigation to a host not on the allowlist (browser host-pinning).
    An absent/empty list allows all."""
    if allow and not _host_allowed(_url_host(url), allow):
        raise ValueError(f"navigation to {_url_host(url)} is not in allowedDomains")

# The JS evaluated in the page to set localStorage items. Kept as a module
# constant so tests can assert it is passed through unchanged.
_LOCAL_STORAGE_JS = (
    "(items)=>{for(const[k,v]of Object.entries(items))localStorage.setItem(k,v)}"
)

# MFA challenge detection heuristics — all operate on NON-secret signals (the page
# URL and HTML structure), never the secret. Mirrors the TS SDK.
_MFA_URL_RE = re.compile(r"mfa|2fa|twofactor|two-factor|otp|/verify|/challenge|verification", re.I)
_MFA_TEXT_RE = re.compile(
    r"enter the[^.<]{0,40}code|verification code|two-factor|one-time code|6-digit code"
    r"|approve[^.<]{0,20}sign-?in|authenticator app",
    re.I,
)
_MFA_INPUT_RE = re.compile(
    r"autocomplete\s*=\s*[\"']one-time-code[\"']|inputmode\s*=\s*[\"']numeric[\"']"
    r"|maxlength\s*=\s*[\"']6[\"']",
    re.I,
)


def apply_browser_login(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    """Apply a browser-login ``plan`` to a duck-typed Playwright sync ``page``.

    Dispatches on ``plan["mode"]`` and mutates the page/context to establish the
    logged-in session. Returns a non-secret summary dict describing what was
    applied — it never includes any cookie/header/storage/form value.

    Raises:
        ValueError: if ``plan`` has no recognised ``mode``.
    """
    mode = plan.get("mode")
    if mode == "cookie":
        return _apply_cookie(page, plan)
    if mode == "header":
        return _apply_header(page, plan)
    if mode == "localStorage":
        return _apply_local_storage(page, plan)
    if mode == "form":
        return _apply_form(page, plan)
    raise ValueError(f"unknown browser-login mode: {mode!r}")


def _summary_base(plan: Mapping[str, Any]) -> Dict[str, Any]:
    """The common, non-secret head of every summary."""
    return {
        "mode": plan.get("mode"),
        "target": plan.get("target"),
        "url": plan.get("url"),
    }


def _apply_cookie(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    cookies: List[Mapping[str, Any]] = list(plan.get("cookies") or [])
    # Validate the destination BEFORE planting any secret state: an off-allowlist
    # url must never leave session cookies in the persistent context (a later caller
    # nav to that host would otherwise transmit them). Fail closed first, exactly as
    # the localStorage branch does.
    _assert_nav_allowed(plan["url"], plan.get("allowedDomains"))
    page.context.add_cookies(cookies)
    page.goto(plan["url"])
    summary = _summary_base(plan)
    summary["authenticated"] = True
    # Names only — never the cookie values.
    summary["cookie_names"] = [str(c.get("name")) for c in cookies]
    return summary


def _apply_header(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    headers: Mapping[str, str] = plan.get("headers") or {}
    # Validate the destination BEFORE planting any secret state: set_extra_http_headers
    # is context-wide and NOT domain-scoped, so an off-allowlist url must never plant an
    # Authorization header a later caller nav would leak. Fail closed first.
    _assert_nav_allowed(plan["url"], plan.get("allowedDomains"))
    page.context.set_extra_http_headers(dict(headers))
    page.goto(plan["url"])
    summary = _summary_base(plan)
    summary["authenticated"] = True
    # Header names only — never the header values.
    summary["header_names"] = list(headers.keys())
    return summary


def _apply_local_storage(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    items: Mapping[str, str] = plan.get("items") or {}
    # Must navigate to the origin first so localStorage is for the right document.
    _assert_nav_allowed(plan["url"], plan.get("allowedDomains"))
    page.goto(plan["url"])
    page.evaluate(_LOCAL_STORAGE_JS, dict(items))
    summary = _summary_base(plan)
    summary["authenticated"] = True
    # Keys only — never the stored values.
    summary["storage_keys"] = list(items.keys())
    return summary


def _page_url(page: Any) -> Any:
    """Read the page's current URL, tolerating a property or a callable (Playwright
    sync exposes ``page.url`` as a property; some fakes use a method)."""
    u = getattr(page, "url", None)
    return u() if callable(u) else u


def _page_content(page: Any) -> str:
    """Read the page HTML (Playwright/Puppeteer ``page.content()``) if available."""
    c = getattr(page, "content", None)
    if callable(c):
        html = c()
        return html if isinstance(html, str) else ""
    return ""


def _extract_prompt_text(html: str) -> Optional[str]:
    """A non-secret, best-effort prompt string from the page's visible text."""
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    m = re.search(
        r"[^.<>]*?(enter the[^.<>]{0,40}code|verification code|one-time code"
        r"|6-digit code|two-factor)[^.<>]*",
        text,
        re.I,
    ) or re.search(r".{0,60}(authenticator|verification|one-time code).{0,60}", text, re.I)
    if not m:
        return None
    return m.group(0).strip()[:160]


def _detect_mfa(page: Any, spec: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Detect an MFA challenge after a form submit using non-secret page signals.

    Returns a non-secret challenge dict ``{kind, promptText, detectedAt,
    challengeId}`` (browser left on the page) or ``None``. Honours
    ``spec['detectBy']`` (default ``auto`` = url|text|input).
    """
    spec = spec or {}
    html = _page_content(page)
    current = _page_url(page)
    url = current if isinstance(current, str) else ""
    url_hit = bool(_MFA_URL_RE.search(url))
    text_hit = bool(_MFA_TEXT_RE.search(html))
    input_hit = bool(_MFA_INPUT_RE.search(html))
    by = spec.get("detectBy", "auto")
    if by == "url":
        detected = url_hit
    elif by == "text":
        detected = text_hit
    elif by == "input":
        detected = input_hit
    else:
        detected = url_hit or text_hit or input_hit
    if not detected:
        return None
    challenge: Dict[str, Any] = {
        "kind": spec.get("kind", "otp"),
        "promptText": spec.get("channelHint")
        or _extract_prompt_text(html)
        or "Multi-factor authentication required",
        "detectedAt": datetime.now(timezone.utc).isoformat(),
        "challengeId": "mfa_" + uuid.uuid4().hex,
    }
    # Carry the configured selectors forward so resolve_mfa can inject the code
    # without an explicit kwarg (the per-credential spec drives it).
    if spec.get("inputSelector") is not None:
        challenge["inputSelector"] = spec["inputSelector"]
    if spec.get("submitSelector") is not None:
        challenge["submitSelector"] = spec["submitSelector"]
    return challenge


def _apply_form(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    actions: List[Mapping[str, Any]] = list(plan.get("actions") or [])
    allow = plan.get("allowedDomains")
    filled_fields = 0
    for action in actions:
        kind = action.get("type")
        if kind == "goto":
            # Navigation allowlist (browser analogue of proxy host-pinning).
            _assert_nav_allowed(action["url"], allow)
            page.goto(action["url"])
        elif kind == "fill":
            page.fill(action["selector"], action["value"])
            # Count only — never the filled value (matches the TS summary contract).
            filled_fields += 1
        elif kind == "click":
            page.click(action["selector"])
        else:
            raise ValueError(f"unknown form action type: {kind!r}")
    # Settle async navigation triggered by the submit before reading url/HTML, so
    # success/MFA detection doesn't race a still-loading page (best-effort).
    wait = getattr(page, "wait_for_load_state", None)
    if callable(wait):
        try:
            wait("networkidle")
        except Exception:  # noqa: BLE001
            pass
    summary = _summary_base(plan)
    summary["filled_fields"] = filled_fields
    # `submitted` mirrors the TS contract: present ONLY when the plan carries
    # successUrlIncludes, and true iff the post-login page URL contains it.
    success_inc = plan.get("successUrlIncludes")
    submitted: Optional[bool] = None
    if success_inc is not None:
        current = _page_url(page)
        submitted = isinstance(current, str) and success_inc in current
        summary["submitted"] = submitted
    # Resolve the outcome: success URL reached -> authenticated; else look for an
    # MFA challenge before declaring success/failure.
    if submitted is True:
        summary["authenticated"] = True
    else:
        mfa = _detect_mfa(page, plan.get("mfa"))
        if mfa is not None:
            summary["authenticated"] = False
            summary["mfa"] = mfa
        else:
            # No success-URL and no MFA -> best-effort success (form submitted, no
            # challenge). With a success-URL configured but unmatched -> not yet in.
            summary["authenticated"] = success_inc is None
    return summary

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

from typing import Any, Dict, List, Mapping

# The JS evaluated in the page to set localStorage items. Kept as a module
# constant so tests can assert it is passed through unchanged.
_LOCAL_STORAGE_JS = (
    "(items)=>{for(const[k,v]of Object.entries(items))localStorage.setItem(k,v)}"
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
    page.context.add_cookies(cookies)
    page.goto(plan["url"])
    summary = _summary_base(plan)
    # Names only — never the cookie values.
    summary["cookie_names"] = [str(c.get("name")) for c in cookies]
    return summary


def _apply_header(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    headers: Mapping[str, str] = plan.get("headers") or {}
    page.context.set_extra_http_headers(dict(headers))
    page.goto(plan["url"])
    summary = _summary_base(plan)
    # Header names only — never the header values.
    summary["header_names"] = list(headers.keys())
    return summary


def _apply_local_storage(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    items: Mapping[str, str] = plan.get("items") or {}
    # Must navigate to the origin first so localStorage is for the right document.
    page.goto(plan["url"])
    page.evaluate(_LOCAL_STORAGE_JS, dict(items))
    summary = _summary_base(plan)
    # Keys only — never the stored values.
    summary["storage_keys"] = list(items.keys())
    return summary


def _page_url(page: Any) -> Any:
    """Read the page's current URL, tolerating a property or a callable (Playwright
    sync exposes ``page.url`` as a property; some fakes use a method)."""
    u = getattr(page, "url", None)
    return u() if callable(u) else u


def _apply_form(page: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    actions: List[Mapping[str, Any]] = list(plan.get("actions") or [])
    filled_fields = 0
    for action in actions:
        kind = action.get("type")
        if kind == "goto":
            page.goto(action["url"])
        elif kind == "fill":
            page.fill(action["selector"], action["value"])
            # Count only — never the filled value (matches the TS summary contract).
            filled_fields += 1
        elif kind == "click":
            page.click(action["selector"])
        else:
            raise ValueError(f"unknown form action type: {kind!r}")
    summary = _summary_base(plan)
    summary["filled_fields"] = filled_fields
    # `submitted` mirrors the TS contract: present ONLY when the plan carries
    # successUrlIncludes, and true iff the post-login page URL contains it. When
    # there is no success hint the key is omitted (a click alone is not "success").
    success_inc = plan.get("successUrlIncludes")
    if success_inc is not None:
        current = _page_url(page)
        summary["submitted"] = isinstance(current, str) and success_inc in current
    return summary

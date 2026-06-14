"""Error types raised by the AgentAuth SDK.

Every non-2xx response from the API is surfaced as an :class:`AgentAuthError`.
The server speaks a single error envelope::

    {"error": {"code": "...", "message": "...", "requestId": "...", "details": ...}}

We map that onto structured attributes so callers can branch on ``code`` /
``status`` instead of parsing strings.
"""

from __future__ import annotations

from typing import Any, Optional


class AgentAuthError(Exception):
    """Raised when the AgentAuth API returns a non-2xx response.

    Attributes:
        status: HTTP status code (e.g. 401, 403, 404, 503).
        code: Machine-readable error code from the envelope (e.g. ``"forbidden"``).
        message: Human-readable message from the envelope.
        request_id: Server-assigned request id for correlation in logs/audit.
        details: Optional structured details (validation errors, etc.).
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        request_id: Optional[str] = None,
        details: Any = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.details = details
        super().__init__(f"[{status} {code}] {message}")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"AgentAuthError(status={self.status!r}, code={self.code!r}, "
            f"message={self.message!r}, request_id={self.request_id!r})"
        )

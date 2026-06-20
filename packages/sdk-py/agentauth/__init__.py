"""AgentAuth — official Python SDK.

The credential vault and identity broker for AI agents. Two clients:

* :class:`HumanClient`  — management plane (session JWT): register, passports,
  deposit (with usage policy), agents, mTLS bind, OAuth start, approvals, audit.
* :class:`AgentAuthClient` — data plane (agent API key): discover and use
  credentials (including resolution by target host), proxy, and browser-login.

All API errors are raised as :class:`AgentAuthError`.
"""

from __future__ import annotations

from .client import AgentAuthClient, HumanClient
from .errors import AgentAuthError, ApprovalPendingError

__version__ = "0.1.0"

__all__ = [
    "AgentAuthClient",
    "HumanClient",
    "AgentAuthError",
    "ApprovalPendingError",
    "__version__",
]

"""
agent_routes.py
---------------
HTTP surface for the conversational agent's backend dependencies.

Two endpoints, both POST:

- ``POST /agent/tool`` — dispatcher for the 9 agent tools defined in
  ``src/agent/tools.py``. The Streamlit page's agent loop calls this
  exactly once per ``tool_use`` block emitted by Claude.

- ``POST /agent/post_alert`` — user-confirmed alert send. **Distinct
  from /agent/tool on purpose**: only the page calls this, and only
  after the analyst has clicked "Approve & send" in the chat UI. The
  agent's tool list does not include it, so a misbehaving model cannot
  fire an alert without the user's explicit consent.

Routing the agent through FastAPI (instead of importing the
repositories directly inside Streamlit) preserves the single-HanaPool-
owner invariant — every other dashboard page already goes through the
API.
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from src.agent.tools import dispatch
from src.alerting.sap_webhook import post_alert_message
from src.common.config import settings
from src.common.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])


def _expected_agent_token() -> str:
    return settings.agent_api_token or settings.sap_api_key


def _require_agent_auth(authorization: str | None = Header(default=None)) -> None:
    """Protect agent HTTP routes in deployed environments.

    Local/mock development stays open unless AGENT_AUTH_REQUIRED=true or an
    AGENT_API_TOKEN/SAP_API_KEY is configured.
    """
    expected = _expected_agent_token()
    auth_required = settings.agent_auth_required or bool(settings.agent_api_token)
    if not auth_required:
        return
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent_auth_not_configured",
        )
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ToolCallRequest(BaseModel):
    """One ``tool_use`` block being relayed to the dispatcher."""

    name: str = Field(..., description="Tool name (must be in TOOL_REGISTRY).")
    args: dict[str, Any] = Field(default_factory=dict)


class ToolCallResponse(BaseModel):
    ok: bool
    result: dict[str, Any]


class PostAlertRequest(BaseModel):
    message: str = Field(
        ...,
        description="Pre-formatted alert message (<=300 chars).",
        max_length=2000,  # generous cap; post_alert_message() owns the real 300-char check
    )


@router.post("/tool", response_model=ToolCallResponse)
async def tool_endpoint(
    req: ToolCallRequest,
    _auth: None = Depends(_require_agent_auth),
) -> ToolCallResponse:
    """Dispatch one agent tool by name and return its structured result.

    ``ok`` is False when the dispatcher returned an error envelope (unknown
    tool, bad args, runtime exception). The page surfaces this to the LLM
    on the next iteration so it can recover.
    """
    result = await dispatch(req.name, req.args)
    ok = "error" not in result
    logger.info(
        "agent.tool.dispatched",
        extra={"tool": req.name, "ok": ok, "args_keys": list((req.args or {}).keys())},
    )
    return ToolCallResponse(ok=ok, result=result)


@router.post("/post_alert")
async def post_alert_endpoint(
    req: PostAlertRequest,
    _auth: None = Depends(_require_agent_auth),
) -> dict[str, Any]:
    """Send a pre-formatted alert. Called only after analyst confirmation."""
    result = await post_alert_message(req.message)
    logger.info(
        "agent.post_alert.dispatched",
        extra={"ok": result.get("ok"), "status": result.get("status")},
    )
    return result

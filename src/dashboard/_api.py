"""
dashboard/_api.py
-----------------
Shared helpers for the Streamlit dashboard pages.

The leading underscore keeps this file from being auto-registered as a
Streamlit page (the ``pages/`` discovery only picks up files in that
folder; this file lives alongside ``app.py`` and is imported, not
rendered).

Every page should funnel its API calls through these helpers so caching
semantics stay consistent and we have one place to change when the
backend contract moves.

Owner: Security Analyst & Visualization Lead
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pandas as pd
import streamlit as st
from src.common.config import settings

# ─── Constants ─────────────────────────────────────────────────────────────

TIMEOUT_SECONDS: float = 3.0
FALLBACK_CSV_PATHS: tuple[Path, ...] = (
    Path("data/samples/sample_logs.csv"),
    Path("data/samples/mock_logs.csv"),
)


# ─── HTTP fetchers ─────────────────────────────────────────────────────────


@st.cache_data(ttl=5, show_spinner=False)
def fetch_metrics() -> dict[str, Any]:
    """Return ``/metrics`` JSON or ``{}`` if the API is unreachable."""
    return _safe_get("/metrics") or {}


@st.cache_data(ttl=5, show_spinner=False)
def fetch_health() -> dict[str, Any]:
    return _safe_get("/health") or {}


@st.cache_data(ttl=5, show_spinner=False)
def fetch_readiness() -> dict[str, Any]:
    return _safe_get("/ready") or {}


@st.cache_data(ttl=5, show_spinner=False)
def fetch_anomalies(limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent anomalies, newest first. Empty on failure."""
    payload = _safe_get("/anomalies", params={"limit": limit}) or {}
    return payload.get("anomalies", [])


def _safe_get(path: str, *, params: dict[str, Any] | None = None) -> Any:
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    try:
        resp = httpx.get(url, params=params, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ─── Fallback data ─────────────────────────────────────────────────────────


@st.cache_data(ttl=30, show_spinner=False)
def load_fallback_logs() -> pd.DataFrame:
    """Load local sample logs — used when the API is down or in tests."""
    for path in FALLBACK_CSV_PATHS:
        if path.exists():
            df = pd.read_csv(path)
            if "datetime" in df.columns:
                df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
            return df
    return pd.DataFrame()


# ─── Shared UI bits ────────────────────────────────────────────────────────


def api_status_banner(metrics_data: dict[str, Any]) -> bool:
    """Render a banner when the API is unreachable. Returns True when live."""
    if metrics_data:
        return True
    st.warning(
        f"API not reachable at {settings.api_base_url}. Showing fallback "
        "data where possible. Start the API with `make api`."
    )
    return False


def dashboard_autorefresh(key: str) -> None:
    """Wire the auto-refresh component if installed. Silent no-op otherwise."""
    try:
        from streamlit_autorefresh import st_autorefresh
    except ImportError:
        return
    interval_ms = settings.dashboard_refresh_seconds * 1000
    st_autorefresh(interval=interval_ms, key=key)


def format_number(value: Any, default: str = "—") -> str:
    """Human-friendly numeric formatter for ``st.metric`` and headers."""
    if value is None or value == "":
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if number == int(number):
        return f"{int(number):,}"
    return f"{number:,.2f}"


def threat_level_color(level: str) -> str:
    """Colour code matching the existing dashboard palette."""
    mapping = {
        "high": "#e74c3c",
        "medium": "#f39c12",
        "low": "#2ecc71",
        "suppressed": "#f39c12",
    }
    return mapping.get((level or "").lower(), "#3498db")


# ─── Sidebar design system ─────────────────────────────────────────────────


def inject_sidebar_css() -> None:
    """Inject the dark-sidebar theme once per page load.

    Call this at module level (outside ``with st.sidebar:``) so the
    ``<style>`` block is hoisted into the page ``<head>`` and the CSS
    selectors targeting the sidebar element apply globally.
    """
    st.markdown(
        """
        <style>
        /* ── Sidebar container ─────────────────────────────────────────── */
        section[data-testid="stSidebar"] {
            background: linear-gradient(160deg, #0d1b2e 0%, #152132 55%, #1a2840 100%) !important;
            border-right: 1px solid #1e3a5f !important;
        }

        /* ── Page-nav links (auto-generated multi-page list) ───────────── */
        section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"],
        section[data-testid="stSidebar"] [data-testid="stNavLink"] {
            border-radius: 8px !important;
            transition: background 0.15s;
        }
        section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] span,
        section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] p,
        section[data-testid="stSidebar"] [data-testid="stNavLink"] span,
        section[data-testid="stSidebar"] [data-testid="stNavLink"] p {
            color: #7c9ab8 !important;
            font-size: 13px !important;
        }
        section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]:hover,
        section[data-testid="stSidebar"] [data-testid="stNavLink"]:hover {
            background: rgba(56, 189, 248, 0.07) !important;
        }
        section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] span,
        section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] p,
        section[data-testid="stSidebar"] [data-testid="stNavLink"][aria-current="page"] span,
        section[data-testid="stSidebar"] [data-testid="stNavLink"][aria-current="page"] p {
            color: #38bdf8 !important;
            font-weight: 600 !important;
        }

        /* ── User-authored content ─────────────────────────────────────── */
        section[data-testid="stSidebar"] .stMarkdown p,
        section[data-testid="stSidebar"] .stMarkdown li,
        section[data-testid="stSidebar"] .stMarkdown span {
            color: #94a3b8 !important;
            font-size: 13px !important;
            line-height: 1.65 !important;
        }
        section[data-testid="stSidebar"] h1,
        section[data-testid="stSidebar"] h2,
        section[data-testid="stSidebar"] h3 {
            color: #e2e8f0 !important;
            letter-spacing: -0.3px !important;
        }
        section[data-testid="stSidebar"] code {
            background: rgba(56, 189, 248, 0.10) !important;
            color: #7dd3fc !important;
            border: 1px solid rgba(56, 189, 248, 0.18) !important;
            padding: 1px 5px !important;
            border-radius: 4px !important;
            font-size: 11.5px !important;
        }
        section[data-testid="stSidebar"] pre,
        section[data-testid="stSidebar"] pre code {
            background: rgba(15, 25, 45, 0.7) !important;
            color: #7dd3fc !important;
            border: 1px solid #1e3a5f !important;
            border-radius: 6px !important;
            font-size: 12px !important;
        }
        section[data-testid="stSidebar"] hr {
            border-top: 1px solid #1e3a5f !important;
            margin: 12px 0 !important;
        }
        section[data-testid="stSidebar"] .stCaptionContainer p,
        section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
            color: #475569 !important;
            font-size: 11px !important;
        }
        section[data-testid="stSidebar"] [data-testid="stExpander"] {
            border: 1px solid #1e3a5f !important;
            border-radius: 8px !important;
            background: rgba(255, 255, 255, 0.02) !important;
        }
        section[data-testid="stSidebar"] [data-testid="stExpander"] summary p {
            color: #94a3b8 !important;
            font-size: 13px !important;
        }
        section[data-testid="stSidebar"] [data-testid="stJson"] {
            background: rgba(0, 0, 0, 0.25) !important;
            border: 1px solid #1e3a5f !important;
            border-radius: 6px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def sidebar_brand(page_label: str) -> None:
    """Render the branded header inside ``with st.sidebar:``.

    Args:
        page_label: Short all-caps label for the current page, e.g.
                    ``"OPERATIONS"`` or ``"DEV / ANALYST"``.
    """
    st.markdown(
        f"""
        <div style="
            padding: 18px 4px 16px;
            text-align: center;
            border-bottom: 1px solid #1e3a5f;
            margin-bottom: 6px;
        ">
            <div style="font-size:26px;margin-bottom:6px;line-height:1">&#x1F6E1;&#xFE0F;</div>
            <div style="
                font-size: 14px;
                font-weight: 700;
                color: #e2e8f0;
                letter-spacing: -0.3px;
                line-height: 1.2;
            ">SAP AI Security</div>
            <div style="
                font-size: 9.5px;
                font-weight: 700;
                letter-spacing: 2px;
                text-transform: uppercase;
                color: #38bdf8;
                margin-top: 5px;
            ">{page_label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def sb_section(title: str) -> str:
    """Return an HTML section-label string for use in ``st.markdown``.

    Renders as a small, spaced, uppercase label with a subtle bottom
    border — separates logical groups within the sidebar.
    """
    return (
        f'<p style="'
        f"font-size:9.5px;"
        f"font-weight:700;"
        f"letter-spacing:1.8px;"
        f"text-transform:uppercase;"
        f"color:#334d6e;"
        f"margin:18px 0 8px;"
        f"padding-bottom:5px;"
        f'border-bottom:1px solid #1e3a5f">'
        f"{title}</p>"
    )


def sb_row(label: str, value: str) -> str:
    """Return an HTML key/value row for sidebar metadata tables."""
    return (
        '<div style="display:flex;justify-content:space-between;'
        'align-items:baseline;padding:3px 0;'
        'border-bottom:1px solid rgba(255,255,255,0.03)">'
        f'<span style="font-size:12px;color:#475569">{label}</span>'
        f'<span style="font-size:12px;color:#94a3b8;font-family:monospace">{value}</span>'
        "</div>"
    )


def sb_status(name: str, ok: bool | None, detail: str = "") -> str:
    """Return an HTML status row with a glowing dot and a pill badge.

    Args:
        name:   Display name of the service.
        ok:     ``True`` = live/healthy, ``False`` = down/error, ``None`` = unknown.
        detail: Optional short detail string appended after the name.
    """
    dot_colour = "#22c55e" if ok is True else "#ef4444" if ok is False else "#64748b"
    glow = f"0 0 6px {dot_colour}99"
    badge_bg = "#14532d" if ok is True else "#7f1d1d" if ok is False else "#1e293b"
    badge_fg = "#86efac" if ok is True else "#fca5a5" if ok is False else "#94a3b8"
    badge_text = "LIVE" if ok is True else "DOWN" if ok is False else "UNKNOWN"
    detail_html = (
        f' <span style="font-size:11px;color:#475569">{detail}</span>' if detail else ""
    )
    return (
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'padding:5px 2px;border-bottom:1px solid rgba(255,255,255,0.03)">'
        '<div style="display:flex;align-items:center;gap:8px">'
        f'<span style="width:7px;height:7px;border-radius:50%;background:{dot_colour};'
        f'flex-shrink:0;display:inline-block;box-shadow:{glow}"></span>'
        f'<span style="font-size:13px;color:#cbd5e1;font-weight:500">{name}</span>'
        f"{detail_html}"
        "</div>"
        f'<span style="background:{badge_bg};color:{badge_fg};padding:1px 8px;'
        f'border-radius:20px;font-size:10px;font-weight:700;letter-spacing:0.8px">'
        f"{badge_text}</span>"
        "</div>"
    )

"""
versioning.py
-------------
Model registry for MLOps tracking.

Every trained model is saved under ``models/<version_tag>/`` as:

- ``model.joblib``     — the fitted estimator
- ``scaler.joblib``    — the fitted StandardScaler
- ``manifest.json``    — metrics, hyperparams, feature columns, model type

A ``models/latest.txt`` file holds the version tag of the currently
active model. Inference code calls ``ModelRegistry.load()`` with no
arguments to pick up whatever ``latest`` points to.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib

from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

MODEL_FILE: str = "model.joblib"
SCALER_FILE: str = "scaler.joblib"
MANIFEST_FILE: str = "manifest.json"
LATEST_POINTER: str = "latest.txt"


class ModelNotFoundError(RuntimeError):
    """Raised when no trained model can be found on disk."""


@dataclass(frozen=True)
class LoadedModel:
    """Container holding a fitted estimator + scaler + manifest metadata."""

    model: Any
    scaler: Any
    manifest: dict[str, Any]

    @property
    def version_tag(self) -> str:
        return str(self.manifest.get("version_tag", "unknown"))

    @property
    def model_type(self) -> str:
        return str(self.manifest.get("model_type", "isolation_forest"))


class ModelRegistry:
    """File-system backed model registry under ``settings.model_dir``."""

    def __init__(self, root: Path | None = None) -> None:
        self._root: Path = root or settings.model_dir
        self._cache: dict[str, LoadedModel] = {}

    # ── Paths ─────────────────────────────────────────────────────────

    @property
    def root(self) -> Path:
        return self._root

    def _version_dir(self, version_tag: str) -> Path:
        return self._root / version_tag

    def _latest_pointer_path(self) -> Path:
        return self._root / LATEST_POINTER

    # ── Save ──────────────────────────────────────────────────────────

    def save(
        self,
        *,
        model: Any,
        scaler: Any,
        model_type: str,
        feature_columns: list[str] | tuple[str, ...],
        hyperparams: dict[str, Any],
        training_samples: int,
        cv_scores: dict[str, Any] | None = None,
        notes: str = "",
    ) -> str:
        """
        Persist *model* + *scaler* + manifest and return the version tag.

        The new version becomes ``latest`` immediately.
        """
        trained_at = utcnow()
        version_tag = _make_version_tag(trained_at)
        version_dir = self._version_dir(version_tag)
        version_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(model, version_dir / MODEL_FILE)
        joblib.dump(scaler, version_dir / SCALER_FILE)

        manifest: dict[str, Any] = {
            "version_tag": version_tag,
            "model_type": model_type,
            "trained_at": trained_at.isoformat(),
            "feature_columns": list(feature_columns),
            "hyperparams": dict(hyperparams),
            "contamination": float(hyperparams.get("contamination", 0.0) or 0.0),
            "training_samples": int(training_samples),
            "cv_scores": dict(cv_scores or {}),
            "is_active": True,
            "notes": notes,
        }
        (version_dir / MANIFEST_FILE).write_text(
            json.dumps(manifest, indent=2, default=str), encoding="utf-8"
        )

        self._latest_pointer_path().write_text(version_tag, encoding="utf-8")
        self._cache.clear()

        logger.info(
            "model_registry.save",
            extra={
                "version_tag": version_tag,
                "model_type": model_type,
                "samples": training_samples,
            },
        )
        return version_tag

    # ── Load ──────────────────────────────────────────────────────────

    def load(self, version_tag: str = "latest") -> LoadedModel:
        """
        Load a model bundle. ``version_tag="latest"`` resolves via the
        pointer file. Raises :class:`ModelNotFoundError` if nothing is
        trained yet.
        """
        resolved = self._resolve_version(version_tag)
        if resolved in self._cache:
            return self._cache[resolved]

        version_dir = self._version_dir(resolved)
        model_path = version_dir / MODEL_FILE
        scaler_path = version_dir / SCALER_FILE
        manifest_path = version_dir / MANIFEST_FILE

        if not (model_path.exists() and scaler_path.exists() and manifest_path.exists()):
            raise ModelNotFoundError(
                f"Model version {resolved!r} is incomplete at {version_dir}. "
                f"Run: python -m scripts.train_model"
            )

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        loaded = LoadedModel(model=model, scaler=scaler, manifest=manifest)
        self._cache[resolved] = loaded

        logger.info(
            "model_registry.load",
            extra={"version_tag": resolved, "model_type": loaded.model_type},
        )
        return loaded

    def invalidate_cache(self) -> None:
        """Drop all cached bundles. Used by tests and after retraining."""
        self._cache.clear()

    # ── Listing ───────────────────────────────────────────────────────

    def list_versions(self) -> list[str]:
        """Return every version tag on disk, newest first."""
        if not self._root.exists():
            return []
        tags = [
            p.name
            for p in self._root.iterdir()
            if p.is_dir() and (p / MANIFEST_FILE).exists()
        ]
        return sorted(tags, reverse=True)

    def current_version(self) -> str | None:
        """Return the currently active version tag, or None if none."""
        pointer = self._latest_pointer_path()
        if not pointer.exists():
            versions = self.list_versions()
            return versions[0] if versions else None
        tag = pointer.read_text(encoding="utf-8").strip()
        return tag or None

    def activate(self, version_tag: str) -> None:
        """Point ``latest`` at *version_tag*. Raises if the version is unknown."""
        if version_tag not in self.list_versions():
            raise ModelNotFoundError(f"Cannot activate unknown version {version_tag!r}")
        self._latest_pointer_path().write_text(version_tag, encoding="utf-8")
        self._cache.clear()
        logger.info("model_registry.activate", extra={"version_tag": version_tag})

    # ── Internal ──────────────────────────────────────────────────────

    def _resolve_version(self, version_tag: str) -> str:
        if version_tag != "latest":
            return version_tag
        current = self.current_version()
        if current is None:
            raise ModelNotFoundError(
                f"No trained model found in {self._root}. "
                f"Run: python -m scripts.train_model"
            )
        return current


# ─── Helpers ───────────────────────────────────────────────────────────────


def _make_version_tag(trained_at: datetime) -> str:
    """Build a sortable, collision-resistant version tag."""
    ts = trained_at.strftime("%Y%m%d-%H%M%S")
    short_hash = hashlib.sha1(uuid.uuid4().bytes, usedforsecurity=False).hexdigest()[:6]
    return f"{ts}-{short_hash}"


# Module-level singleton.
registry: ModelRegistry = ModelRegistry()

"""
dbscan_detector.py
------------------
Secondary anomaly detector based on DBSCAN clustering.

DBSCAN assigns a label of ``-1`` to outliers (noise points). This module
wraps DBSCAN with a ``decision_function``-like interface so it's a drop-in
alternative to ``sklearn.ensemble.IsolationForest`` in the rest of the
pipeline. The "score" is a signed distance from the nearest core point:
points labeled ``-1`` receive the most negative scores.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.neighbors import NearestNeighbors

from src.common.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DBSCANDetectorParams:
    eps: float = 0.8
    min_samples: int = 3


class DBSCANDetector:
    """
    Wrap a DBSCAN clustering as an anomaly detector.

    Usage::

        det = DBSCANDetector()
        det.fit(X_scaled)
        scores = det.decision_function(X_scaled)  # lower = more anomalous
    """

    def __init__(self, eps: float = 0.8, min_samples: int = 3) -> None:
        self.params = DBSCANDetectorParams(eps=eps, min_samples=min_samples)
        self._dbscan: DBSCAN | None = None
        self._core_nn: NearestNeighbors | None = None
        self._labels_: np.ndarray | None = None
        self._max_distance: float = 1.0

    # ── sklearn-like API ──────────────────────────────────────────────

    def fit(self, X: np.ndarray) -> DBSCANDetector:
        self._dbscan = DBSCAN(eps=self.params.eps, min_samples=self.params.min_samples)
        self._labels_ = self._dbscan.fit_predict(X)

        core_mask = np.zeros(len(X), dtype=bool)
        core_mask[self._dbscan.core_sample_indices_] = True
        core_points = X[core_mask]

        if len(core_points) == 0:
            # Degenerate case: no core points found (eps too small).
            logger.warning(
                "dbscan.no_core_points",
                extra={"eps": self.params.eps, "min_samples": self.params.min_samples},
            )
            self._core_nn = None
            self._max_distance = 1.0
            return self

        self._core_nn = NearestNeighbors(n_neighbors=1).fit(core_points)
        distances, _ = self._core_nn.kneighbors(X)
        self._max_distance = float(distances.max()) or 1.0
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """
        Return anomaly scores where lower = more anomalous.

        Scale is roughly symmetric around 0:
        - core points → ~0
        - near-cluster points → slightly negative
        - outliers (label = -1) → strongly negative
        """
        if self._core_nn is None:
            return np.zeros(len(X), dtype="float64")

        distances, _ = self._core_nn.kneighbors(X)
        normalized = distances.flatten() / self._max_distance
        # Map [0, 1] distances to [0.1, -0.5] roughly so they overlap with
        # IsolationForest score ranges and share thresholds.
        return 0.1 - 0.6 * normalized

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return +1 for normal points, -1 for anomalies (sklearn convention)."""
        scores = self.decision_function(X)
        return np.where(scores < 0, -1, 1)

    # ── Introspection ─────────────────────────────────────────────────

    def get_params(self) -> dict[str, Any]:
        return {"eps": self.params.eps, "min_samples": self.params.min_samples}

    @property
    def n_clusters_(self) -> int:
        if self._labels_ is None:
            return 0
        unique = set(self._labels_.tolist())
        unique.discard(-1)
        return len(unique)

    @property
    def n_outliers_(self) -> int:
        if self._labels_ is None:
            return 0
        return int((self._labels_ == -1).sum())

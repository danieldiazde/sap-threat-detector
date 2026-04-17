"""Unit tests for src/model/versioning.py — save/load round-trip."""

from __future__ import annotations

import json

import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.model.versioning import ModelNotFoundError, ModelRegistry


class TestModelRegistry:
    def test_save_and_load(self, tmp_model_registry: ModelRegistry):
        model = IsolationForest(random_state=42)
        model.fit([[0, 0], [1, 1], [2, 2]])
        scaler = StandardScaler()
        scaler.fit([[0, 0], [1, 1], [2, 2]])

        tag = tmp_model_registry.save(
            model=model,
            scaler=scaler,
            model_type="isolation_forest",
            feature_columns=["a", "b"],
            hyperparams={"contamination": 0.05},
            training_samples=3,
        )

        loaded = tmp_model_registry.load(tag)
        assert loaded.version_tag == tag
        assert loaded.model_type == "isolation_forest"

    def test_load_latest(self, tmp_model_registry: ModelRegistry):
        model = IsolationForest(random_state=42)
        model.fit([[0, 0], [1, 1]])
        scaler = StandardScaler().fit([[0, 0], [1, 1]])

        tag = tmp_model_registry.save(
            model=model, scaler=scaler, model_type="isolation_forest",
            feature_columns=["a"], hyperparams={}, training_samples=2,
        )

        loaded = tmp_model_registry.load("latest")
        assert loaded.version_tag == tag

    def test_load_nonexistent_raises(self, tmp_model_registry: ModelRegistry):
        with pytest.raises(ModelNotFoundError):
            tmp_model_registry.load("nonexistent-version")

    def test_list_versions(self, tmp_model_registry: ModelRegistry):
        model = IsolationForest(random_state=42)
        model.fit([[0, 0]])
        scaler = StandardScaler().fit([[0, 0]])

        tmp_model_registry.save(
            model=model, scaler=scaler, model_type="isolation_forest",
            feature_columns=[], hyperparams={}, training_samples=1,
        )
        tmp_model_registry.save(
            model=model, scaler=scaler, model_type="dbscan",
            feature_columns=[], hyperparams={}, training_samples=1,
        )

        versions = tmp_model_registry.list_versions()
        assert len(versions) == 2

    def test_manifest_contents(self, tmp_model_registry: ModelRegistry):
        model = IsolationForest(random_state=42)
        model.fit([[0, 0], [1, 1]])
        scaler = StandardScaler().fit([[0, 0], [1, 1]])

        tag = tmp_model_registry.save(
            model=model, scaler=scaler, model_type="isolation_forest",
            feature_columns=["a", "b"],
            hyperparams={"contamination": 0.05, "n_estimators": 100},
            training_samples=2,
            cv_scores={"mean": 0.05, "std": 0.01},
            notes="test",
        )

        manifest_path = tmp_model_registry.root / tag / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        assert manifest["version_tag"] == tag
        assert manifest["feature_columns"] == ["a", "b"]
        assert manifest["training_samples"] == 2
        assert manifest["cv_scores"]["mean"] == 0.05

    def test_activate(self, tmp_model_registry: ModelRegistry):
        model = IsolationForest(random_state=42)
        model.fit([[0, 0]])
        scaler = StandardScaler().fit([[0, 0]])

        tag1 = tmp_model_registry.save(
            model=model, scaler=scaler, model_type="isolation_forest",
            feature_columns=[], hyperparams={}, training_samples=1,
        )
        tag2 = tmp_model_registry.save(
            model=model, scaler=scaler, model_type="isolation_forest",
            feature_columns=[], hyperparams={}, training_samples=1,
        )

        assert tmp_model_registry.current_version() == tag2
        tmp_model_registry.activate(tag1)
        assert tmp_model_registry.current_version() == tag1

    def test_activate_unknown_raises(self, tmp_model_registry: ModelRegistry):
        with pytest.raises(ModelNotFoundError):
            tmp_model_registry.activate("does-not-exist")

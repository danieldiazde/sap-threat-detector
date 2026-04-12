"""ANALYZE + DETECT — feature engineering, training, inference, versioning."""

from src.model.features import extract_features, feature_matrix
from src.model.predict import anomalies_only, predict, reset_active_model
from src.model.schema import FEATURE_COLUMNS, REQUIRED_LOG_COLUMNS, InvalidLogSchemaError
from src.model.train import train
from src.model.versioning import LoadedModel, ModelNotFoundError, ModelRegistry, registry

__all__ = [
    "extract_features",
    "feature_matrix",
    "predict",
    "anomalies_only",
    "reset_active_model",
    "train",
    "FEATURE_COLUMNS",
    "REQUIRED_LOG_COLUMNS",
    "InvalidLogSchemaError",
    "LoadedModel",
    "ModelNotFoundError",
    "ModelRegistry",
    "registry",
]

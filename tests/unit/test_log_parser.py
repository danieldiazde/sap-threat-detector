"""Unit tests for src/ingestion/log_parser.py."""

from __future__ import annotations

import pandas as pd
import pytest
from src.ingestion.log_parser import normalize_columns, parse_raw_response
from src.model.schema import InvalidLogSchemaError, validate_schema


class TestParseRawResponse:
    def test_bare_list(self):
        payload = [
            {"datetime": "2026-04-04 14:00:00", "source_ip": "10.0.0.1",
             "status": "200", "event_description": "GET /"},
        ]
        df = parse_raw_response(payload)
        assert len(df) == 1
        assert "source_ip" in df.columns

    def test_wrapped_logs_key(self):
        payload = {
            "logs": [
                {"datetime": "2026-04-04 14:00:00", "source_ip": "10.0.0.1",
                 "status": "200", "event_description": "GET /"},
            ]
        }
        df = parse_raw_response(payload)
        assert len(df) == 1

    def test_wrapped_data_key(self):
        payload = {"data": [{"datetime": "x", "source_ip": "y", "status": "z", "event_description": "w"}]}
        df = parse_raw_response(payload)
        assert len(df) == 1

    def test_none_returns_empty(self):
        assert parse_raw_response(None).empty

    def test_empty_list_returns_empty(self):
        assert parse_raw_response([]).empty

    def test_unknown_envelope_returns_empty(self):
        assert parse_raw_response({"foo": "bar"}).empty


class TestNormalizeColumns:
    def test_alias_timestamp(self):
        df = pd.DataFrame([{"timestamp": "2026-04-04 14:00:00", "ip": "10.0.0.1"}])
        result = normalize_columns(df)
        assert "datetime" in result.columns
        assert "source_ip" in result.columns

    def test_already_canonical(self):
        df = pd.DataFrame([{"datetime": "x", "source_ip": "y"}])
        result = normalize_columns(df)
        assert "datetime" in result.columns

    def test_empty_passthrough(self):
        assert normalize_columns(pd.DataFrame()).empty


class TestValidateSchema:
    def test_valid_passes(self):
        df = pd.DataFrame([{
            "datetime": "x", "source_ip": "y",
            "status": "z", "event_description": "w",
        }])
        result = validate_schema(df)
        assert len(result) == 1

    def test_missing_column_raises(self):
        df = pd.DataFrame([{"datetime": "x", "source_ip": "y"}])
        with pytest.raises(InvalidLogSchemaError) as exc_info:
            validate_schema(df)
        assert "status" in exc_info.value.missing or "event_description" in exc_info.value.missing

    def test_empty_passes(self):
        assert validate_schema(pd.DataFrame()).empty

"""Authoritative Arrow/Parquet IO helpers."""

from .parquet import (
    DEFAULT_MAXIMUM_BUFFERED_ROWS,
    ParquetDependencyError,
    ParquetWriteReport,
    ParquetWriteError,
    arrow_schema_for_table,
    write_parquet_dataset,
    write_parquet_table,
    write_parquet_table_with_report,
)
from .evidence_fixtures import EvidenceFixtureWriteResult, write_evidence_fixture_bundle
from .observer_views import (
    ObserverViewWriteResult,
    write_observer_evaluator_sidecars,
    write_observer_view_bundle,
)
from .sampling_artifacts import SamplingArtifactWriteResult, write_sampling_artifact_bundle
from .validation_artifacts import ValidationArtifactWriteResult, write_validation_artifact_bundle
from .metrics_artifacts import MetricsArtifactWriteResult, write_metrics_artifact_bundle
from .baseline_artifacts import BaselineArtifactWriteResult, write_baseline_artifact_bundle

__all__ = [
    "ParquetDependencyError",
    "ParquetWriteReport",
    "ParquetWriteError",
    "DEFAULT_MAXIMUM_BUFFERED_ROWS",
    "EvidenceFixtureWriteResult",
    "ObserverViewWriteResult",
    "SamplingArtifactWriteResult",
    "ValidationArtifactWriteResult",
    "MetricsArtifactWriteResult",
    "arrow_schema_for_table",
    "write_parquet_dataset",
    "write_parquet_table",
    "write_parquet_table_with_report",
    "write_evidence_fixture_bundle",
    "write_observer_view_bundle",
    "write_observer_evaluator_sidecars",
    "write_sampling_artifact_bundle",
    "write_validation_artifact_bundle",
    "write_metrics_artifact_bundle",
    "BaselineArtifactWriteResult",
    "write_baseline_artifact_bundle",
]

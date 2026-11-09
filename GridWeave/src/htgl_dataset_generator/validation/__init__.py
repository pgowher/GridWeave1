"""Fail-closed S13 validation and production artifact gates."""

from .engine import (
    FAIL,
    NOT_APPLICABLE,
    NOT_EXECUTED,
    PASS,
    JointValidationError,
    ValidationCheckFailure,
    build_joint_validation,
    build_run_scenario_record,
    require_validation_release,
    validation_issues_are_release_eligible,
)
from .models import (
    ArtifactVerificationInput,
    CheckOutcome,
    PerformanceObservation,
    StagePerformanceObservation,
    RegisteredValidationCheck,
    ReplicateExecutionEvidence,
    ValidationBuild,
    ValidationCheckSpec,
    ValidationInput,
)
from .profiles import (
    ValidationThresholdProfile,
    ValidationThresholdProfileError,
    load_validation_threshold_profile,
)
from .registry import VALIDATOR_VERSION, core_check_specs

from .production_rules import (
    ProductionRuleAuditReport,
    ProductionRuleIssue,
    ProductionRuleViolation,
    audit_repository_final_rules,
    audit_resolved_config,
    validate_population_metric_eligibility,
    validate_publication_gate,
    validate_required_check_execution,
    validate_release_table_privacy,
)

__all__ = [
    "ArtifactVerificationInput",
    "CheckOutcome",
    "FAIL",
    "JointValidationError",
    "NOT_APPLICABLE",
    "NOT_EXECUTED",
    "PASS",
    "PerformanceObservation",
    "StagePerformanceObservation",
    "ProductionRuleAuditReport",
    "ProductionRuleIssue",
    "ProductionRuleViolation",
    "RegisteredValidationCheck",
    "ReplicateExecutionEvidence",
    "VALIDATOR_VERSION",
    "ValidationBuild",
    "ValidationCheckFailure",
    "ValidationCheckSpec",
    "ValidationInput",
    "ValidationThresholdProfile",
    "ValidationThresholdProfileError",
    "audit_repository_final_rules",
    "audit_resolved_config",
    "build_joint_validation",
    "build_run_scenario_record",
    "core_check_specs",
    "load_validation_threshold_profile",
    "require_validation_release",
    "validate_population_metric_eligibility",
    "validate_publication_gate",
    "validate_required_check_execution",
    "validate_release_table_privacy",
    "validation_issues_are_release_eligible",
]

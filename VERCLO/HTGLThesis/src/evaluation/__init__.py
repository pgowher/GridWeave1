"""Reproducible VERCLO fault campaigns and verification-policy comparisons."""

from .campaign import (
    CampaignReport,
    EvaluationScenario,
    build_reference_scenarios,
    run_reference_campaign,
)
from .distributed_faults import PBFTFaultProfile, SimulatedPBFTClient
from .fault_injection import FaultInjectionResult, FaultInjector, FaultKind, FaultSpec
from .policy_comparison import ComparisonDecision, ComparisonPolicy, PolicyComparator
from .network_study import NetworkStudyConfig, run_network_backend_study
from .p13_extension_study import (
    ExtensionStudyConfig,
    run_local_extension_study,
    run_remote_extension_study,
    write_extension_results,
)

__all__ = [
    "CampaignReport",
    "ComparisonDecision",
    "ComparisonPolicy",
    "EvaluationScenario",
    "FaultInjectionResult",
    "FaultInjector",
    "FaultKind",
    "FaultSpec",
    "PBFTFaultProfile",
    "NetworkStudyConfig",
    "ExtensionStudyConfig",
    "PolicyComparator",
    "SimulatedPBFTClient",
    "build_reference_scenarios",
    "run_reference_campaign",
    "run_network_backend_study",
    "run_local_extension_study",
    "run_remote_extension_study",
    "write_extension_results",
]

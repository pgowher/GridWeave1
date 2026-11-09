"""PaEGen: versioned privileged case generation for PaEForge experiments."""

from .compiler import build_paegen, compile_paegen_results
from .export import export_paegen
from .models import (
    FECM_MODEL_VERSION,
    PAEGEN_INTERFACE_VERSION,
    PAEGEN_SCHEMA_VERSION,
    PaEGenArtifact,
    PaEGenBuild,
    PaEGenExportResult,
    PaEGenReplica,
)
from .validation import validate_paegen_build
from .benchmark_contract import (
    PaEBenchStudyContract,
    load_benchmark_study_contract,
)
from .smart_grid import (
    REQUIRED_SMART_GRID_SCENARIOS,
    SmartGridScenarioDefinition,
    compile_smart_grid_benchmark,
    load_smart_grid_scenarios,
)
from .adversarial import (
    AdversarialCampaign,
    AdversarialControlBundle,
    AdversarialFixtureResult,
    compile_adversarial_campaign,
    load_adversarial_controls,
    validate_adversarial_campaign,
    AdversarialExportResult,
    export_adversarial_campaign,
)

__all__ = [
    "FECM_MODEL_VERSION",
    "PAEGEN_INTERFACE_VERSION",
    "PAEGEN_SCHEMA_VERSION",
    "PaEGenArtifact",
    "PaEGenBuild",
    "PaEGenExportResult",
    "PaEGenReplica",
    "build_paegen",
    "compile_paegen_results",
    "export_paegen",
    "validate_paegen_build",
    "PaEBenchStudyContract",
    "load_benchmark_study_contract",
    "REQUIRED_SMART_GRID_SCENARIOS",
    "SmartGridScenarioDefinition",
    "compile_smart_grid_benchmark",
    "load_smart_grid_scenarios",
    "AdversarialCampaign",
    "AdversarialControlBundle",
    "AdversarialFixtureResult",
    "compile_adversarial_campaign",
    "load_adversarial_controls",
    "validate_adversarial_campaign",
    "AdversarialExportResult",
    "export_adversarial_campaign",
]

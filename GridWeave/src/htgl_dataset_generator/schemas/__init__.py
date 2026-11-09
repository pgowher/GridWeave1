"""Schema contract loading, model generation, and validation."""

from .contract import (
    ContractSpec,
    FieldSpec,
    SchemaValidationError,
    TableSpec,
    build_model_classes,
    compute_contract_fingerprint,
    compute_table_fingerprint,
    export_arrow_schema,
    export_all_arrow_schemas,
    load_contract,
    load_golden_fixture,
    validate_golden_fixture,
    validate_record,
)

__all__ = [
    "ContractSpec",
    "FieldSpec",
    "SchemaValidationError",
    "TableSpec",
    "build_model_classes",
    "compute_contract_fingerprint",
    "compute_table_fingerprint",
    "export_arrow_schema",
    "export_all_arrow_schemas",
    "load_contract",
    "load_golden_fixture",
    "validate_golden_fixture",
    "validate_record",
]

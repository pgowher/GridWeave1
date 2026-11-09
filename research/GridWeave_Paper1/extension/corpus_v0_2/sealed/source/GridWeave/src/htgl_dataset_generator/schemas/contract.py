"""Contract-locked schema source, model generation, and record validation.

The machine contract in ``schemas/htgl_contract_v1.json`` is the single source
of truth for P0. Runtime models and Arrow logical schema JSON are derived from
that file; callers should not hand-maintain parallel schema definitions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, make_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Union, get_args, get_origin
import hashlib
import json
import os
import re


CONTRACT_ENV = "HTGL_CONTRACT_PATH"
DEFAULT_CONTRACT_RELATIVE_PATH = Path("schemas") / "htgl_contract_v1.json"
DEFAULT_GOLDEN_RELATIVE_PATH = Path("tests") / "golden" / "golden_fixture_v1.json"
TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
FIXED_SIZE_BINARY_RE = re.compile(r"^fixed_size_binary\[(\d+)\]$")
LIST_RE = re.compile(r"^list<(.+)>$")


class SchemaValidationError(ValueError):
    """Raised when a record, schema, dictionary, or fixture violates contract."""


@dataclass(frozen=True)
class FieldSpec:
    name: str
    logical_type: str
    nullable: bool
    dictionary_source: str | None
    privacy_class: str
    description: str
    semantic_invariant: str


@dataclass(frozen=True)
class TableSpec:
    schema_id: str
    table_name: str
    schema_version: str
    source_document: str
    parquet_file: str
    privacy_class: str
    schema_fingerprint: str
    fields: tuple[FieldSpec, ...]

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(field_spec.name for field_spec in self.fields)

    def field(self, name: str) -> FieldSpec:
        for field_spec in self.fields:
            if field_spec.name == name:
                return field_spec
        raise KeyError(f"{self.table_name}: unknown field {name!r}")


@dataclass(frozen=True)
class ContractSpec:
    contract_id: str
    contract_version: str
    source_hierarchy: Mapping[str, str]
    generator_boundary: str
    claim_scale_terms: Mapping[str, str]
    dictionaries: Mapping[str, tuple[str, ...]]
    tables: tuple[TableSpec, ...]
    contract_fingerprint: str
    path: Path

    @property
    def table_names(self) -> tuple[str, ...]:
        return tuple(table.table_name for table in self.tables)

    def table(self, name: str) -> TableSpec:
        for table in self.tables:
            if table.table_name == name:
                return table
        raise KeyError(f"unknown table {name!r}")

    def dictionary_values(self, dictionary_name: str) -> tuple[str, ...]:
        try:
            return self.dictionaries[dictionary_name]
        except KeyError as exc:
            raise SchemaValidationError(
                f"dictionary {dictionary_name!r} is not defined in contract"
            ) from exc


def _repo_root_from(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / DEFAULT_CONTRACT_RELATIVE_PATH).exists():
            return candidate
    raise FileNotFoundError(
        f"cannot locate {DEFAULT_CONTRACT_RELATIVE_PATH} from {start}"
    )


def _default_contract_path() -> Path:
    env_path = os.environ.get(CONTRACT_ENV)
    if env_path:
        return Path(env_path).expanduser().resolve()
    return _repo_root_from(Path(__file__)) / DEFAULT_CONTRACT_RELATIVE_PATH


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _table_to_core_dict(table: TableSpec) -> dict[str, Any]:
    data = asdict(table)
    data.pop("schema_fingerprint", None)
    return data


def _contract_to_core_dict(contract: ContractSpec) -> dict[str, Any]:
    data = {
        "contract_id": contract.contract_id,
        "contract_version": contract.contract_version,
        "source_hierarchy": dict(contract.source_hierarchy),
        "generator_boundary": contract.generator_boundary,
        "claim_scale_terms": dict(contract.claim_scale_terms),
        "dictionaries": {
            name: list(values) for name, values in contract.dictionaries.items()
        },
        "tables": [asdict(table) for table in contract.tables],
    }
    return data


def compute_table_fingerprint(table: TableSpec) -> str:
    """Return the stable SHA-256 fingerprint for a table schema."""

    return hashlib.sha256(_canonical_json(_table_to_core_dict(table)).encode()).hexdigest()


def compute_contract_fingerprint(contract: ContractSpec) -> str:
    """Return the stable SHA-256 fingerprint for the entire schema contract."""

    return hashlib.sha256(
        _canonical_json(_contract_to_core_dict(contract)).encode()
    ).hexdigest()


def load_contract(path: str | os.PathLike[str] | None = None) -> ContractSpec:
    """Load and verify the contract source of truth."""

    contract_path = Path(path).resolve() if path is not None else _default_contract_path()
    raw = json.loads(contract_path.read_text(encoding="utf-8"))
    dictionaries = {
        name: tuple(values) for name, values in raw["dictionaries"].items()
    }
    tables: list[TableSpec] = []
    for table_raw in raw["tables"]:
        table = TableSpec(
            schema_id=table_raw["schema_id"],
            table_name=table_raw["table_name"],
            schema_version=table_raw["schema_version"],
            source_document=table_raw["source_document"],
            parquet_file=table_raw["parquet_file"],
            privacy_class=table_raw["privacy_class"],
            schema_fingerprint=table_raw["schema_fingerprint"],
            fields=tuple(FieldSpec(**field_raw) for field_raw in table_raw["fields"]),
        )
        computed = compute_table_fingerprint(table)
        if computed != table.schema_fingerprint:
            raise SchemaValidationError(
                f"{table.table_name}: stored schema fingerprint "
                f"{table.schema_fingerprint} does not match computed {computed}"
            )
        for field_spec in table.fields:
            if field_spec.dictionary_source is not None:
                if field_spec.dictionary_source not in dictionaries:
                    raise SchemaValidationError(
                        f"{table.table_name}.{field_spec.name}: unknown dictionary "
                        f"{field_spec.dictionary_source!r}"
                    )
        tables.append(table)

    contract = ContractSpec(
        contract_id=raw["contract_id"],
        contract_version=raw["contract_version"],
        source_hierarchy=raw["source_hierarchy"],
        generator_boundary=raw["generator_boundary"],
        claim_scale_terms=raw["claim_scale_terms"],
        dictionaries=dictionaries,
        tables=tuple(tables),
        contract_fingerprint=raw["contract_fingerprint"],
        path=contract_path,
    )
    computed_contract = compute_contract_fingerprint(contract)
    if computed_contract != contract.contract_fingerprint:
        raise SchemaValidationError(
            f"contract fingerprint {contract.contract_fingerprint} does not match "
            f"computed {computed_contract}"
        )
    return contract


def export_arrow_schema(table: TableSpec) -> dict[str, Any]:
    """Build the Arrow logical schema JSON document for one table."""

    return {
        "schema_id": table.schema_id,
        "schema_version": table.schema_version,
        "schema_fingerprint": table.schema_fingerprint,
        "table_name": table.table_name,
        "format": "arrow-logical-schema-json",
        "fields": [
            {
                "name": field_spec.name,
                "type": field_spec.logical_type,
                "nullable": field_spec.nullable,
                "metadata": {
                    "dictionary_source": field_spec.dictionary_source,
                    "privacy_class": field_spec.privacy_class,
                    "semantic_invariant": field_spec.semantic_invariant,
                },
            }
            for field_spec in table.fields
        ],
    }


def export_all_arrow_schemas(
    contract: ContractSpec, output_dir: str | os.PathLike[str]
) -> None:
    """Write Arrow logical schema JSON files derived from the contract."""

    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    for table in contract.tables:
        path = target / f"{table.table_name}.arrow.json"
        path.write_text(
            json.dumps(export_arrow_schema(table), indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )


def _is_optional_type(python_type: Any) -> bool:
    return get_origin(python_type) is Union and type(None) in get_args(python_type)


def _python_type_for_logical(logical_type: str, nullable: bool) -> Any:
    list_match = LIST_RE.match(logical_type)
    if list_match:
        inner = _python_type_for_logical(list_match.group(1), False)
        result: Any = list[inner]  # type: ignore[index]
    elif logical_type in {"string", "large_string", "dictionary<string>"}:
        result = str
    elif logical_type in {"int32", "int64"}:
        result = int
    elif logical_type in {"float32", "float64"}:
        result = float
    elif logical_type == "bool":
        result = bool
    elif logical_type == "timestamp[us, UTC]":
        result = str
    elif FIXED_SIZE_BINARY_RE.match(logical_type):
        result = Union[str, bytes]
    else:
        raise SchemaValidationError(f"unsupported logical type {logical_type!r}")
    return Optional[result] if nullable else result


def _check_scalar_type(field_spec: FieldSpec, value: Any, contract: ContractSpec) -> None:
    logical_type = field_spec.logical_type
    if logical_type in {"string", "large_string", "dictionary<string>"}:
        if not isinstance(value, str):
            raise SchemaValidationError(
                f"{field_spec.name}: expected {logical_type}, got {type(value).__name__}"
            )
        if field_spec.dictionary_source:
            values = contract.dictionary_values(field_spec.dictionary_source)
            if value not in values:
                raise SchemaValidationError(
                    f"{field_spec.name}: {value!r} is not in dictionary "
                    f"{field_spec.dictionary_source}"
                )
    elif logical_type in {"int32", "int64"}:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaValidationError(
                f"{field_spec.name}: expected integer {logical_type}, got "
                f"{type(value).__name__}"
            )
        if logical_type == "int32" and not -(2**31) <= value < 2**31:
            raise SchemaValidationError(f"{field_spec.name}: int32 value out of range")
        if logical_type == "int64" and not -(2**63) <= value < 2**63:
            raise SchemaValidationError(f"{field_spec.name}: int64 value out of range")
    elif logical_type in {"float32", "float64"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SchemaValidationError(
                f"{field_spec.name}: expected floating point {logical_type}, got "
                f"{type(value).__name__}"
            )
    elif logical_type == "bool":
        if not isinstance(value, bool):
            raise SchemaValidationError(
                f"{field_spec.name}: expected bool, got {type(value).__name__}"
            )
    elif logical_type == "timestamp[us, UTC]":
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise SchemaValidationError(f"{field_spec.name}: timestamp must be UTC-aware")
        elif isinstance(value, str):
            if TIMESTAMP_RE.match(value) is None:
                raise SchemaValidationError(
                    f"{field_spec.name}: timestamp must be ISO-8601 with Z or offset"
                )
        else:
            raise SchemaValidationError(
                f"{field_spec.name}: expected timestamp string/datetime, got "
                f"{type(value).__name__}"
            )
    else:
        fixed_size = FIXED_SIZE_BINARY_RE.match(logical_type)
        if fixed_size is None:
            raise SchemaValidationError(f"{field_spec.name}: unsupported type {logical_type}")
        size = int(fixed_size.group(1))
        if isinstance(value, bytes):
            if len(value) != size:
                raise SchemaValidationError(
                    f"{field_spec.name}: expected {size} bytes, got {len(value)}"
                )
        elif isinstance(value, str):
            if len(value) != size * 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
                raise SchemaValidationError(
                    f"{field_spec.name}: expected {size}-byte hex string"
                )
        else:
            raise SchemaValidationError(
                f"{field_spec.name}: expected bytes or hex string, got "
                f"{type(value).__name__}"
            )


def _check_value(field_spec: FieldSpec, value: Any, contract: ContractSpec) -> None:
    if value is None:
        if not field_spec.nullable:
            raise SchemaValidationError(f"{field_spec.name}: null is not allowed")
        return

    list_match = LIST_RE.match(field_spec.logical_type)
    if list_match:
        if not isinstance(value, list):
            raise SchemaValidationError(
                f"{field_spec.name}: expected list, got {type(value).__name__}"
            )
        inner_spec = FieldSpec(
            name=field_spec.name,
            logical_type=list_match.group(1),
            nullable=False,
            dictionary_source=field_spec.dictionary_source,
            privacy_class=field_spec.privacy_class,
            description=field_spec.description,
            semantic_invariant=field_spec.semantic_invariant,
        )
        for index, item in enumerate(value):
            try:
                _check_value(inner_spec, item, contract)
            except SchemaValidationError as exc:
                raise SchemaValidationError(
                    f"{field_spec.name}[{index}]: {exc}"
                ) from exc
        return

    _check_scalar_type(field_spec, value, contract)


def validate_record(
    contract: ContractSpec, table_name: str, record: Mapping[str, Any]
) -> None:
    """Validate one record against table columns, nullability, and dictionaries."""

    table = contract.table(table_name)
    expected = set(table.field_names)
    observed = set(record.keys())
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    if missing:
        raise SchemaValidationError(f"{table_name}: missing required columns {missing}")
    if extra:
        raise SchemaValidationError(f"{table_name}: unknown columns {extra}")
    for field_spec in table.fields:
        try:
            _check_value(field_spec, record[field_spec.name], contract)
        except SchemaValidationError as exc:
            raise SchemaValidationError(
                f"{table_name}.{field_spec.name}: {exc}"
            ) from exc


def _class_name_for_table(table_name: str) -> str:
    return "".join(part.capitalize() for part in table_name.split("_"))


def build_model_classes(contract: ContractSpec) -> dict[str, type[Any]]:
    """Generate frozen dataclass model classes from the contract source."""

    models: dict[str, type[Any]] = {}
    for table in contract.tables:
        model_fields = [
            (
                field_spec.name,
                _python_type_for_logical(field_spec.logical_type, field_spec.nullable),
            )
            for field_spec in table.fields
        ]

        def __post_init__(self: Any, _table_name: str = table.table_name) -> None:
            validate_record(contract, _table_name, asdict(self))

        cls = make_dataclass(
            _class_name_for_table(table.table_name),
            model_fields,
            namespace={
                "__post_init__": __post_init__,
                "__doc__": f"Generated model for {table.schema_id}.",
                "_schema_id": table.schema_id,
                "_schema_version": table.schema_version,
                "_table_name": table.table_name,
            },
            frozen=True,
        )
        models[table.table_name] = cls
    return models


def load_golden_fixture(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Load the Step 1 golden fixture JSON."""

    if path is None:
        root = _repo_root_from(Path(__file__))
        path = root / DEFAULT_GOLDEN_RELATIVE_PATH
    fixture_path = Path(path)
    return json.loads(fixture_path.read_text(encoding="utf-8"))


def _require_non_empty(fixture: Mapping[str, Any], table_names: Iterable[str]) -> None:
    for table_name in table_names:
        rows = fixture.get(table_name)
        if not isinstance(rows, list) or not rows:
            raise SchemaValidationError(f"golden fixture missing non-empty {table_name}")


def validate_golden_fixture(
    contract: ContractSpec, fixture: Mapping[str, Any] | None = None
) -> None:
    """Validate the golden fixture against schemas and P0 coverage requirements."""

    data = fixture if fixture is not None else load_golden_fixture()
    expected = set(contract.table_names)
    observed = set(data.keys())
    missing_tables = sorted(expected - observed)
    extra_tables = sorted(observed - expected)
    if missing_tables:
        raise SchemaValidationError(f"golden fixture missing tables {missing_tables}")
    if extra_tables:
        raise SchemaValidationError(f"golden fixture has unknown tables {extra_tables}")

    _require_non_empty(data, contract.table_names)
    for table_name, rows in data.items():
        if not isinstance(rows, list):
            raise SchemaValidationError(f"{table_name}: fixture table must be a list")
        for index, record in enumerate(rows):
            if not isinstance(record, Mapping):
                raise SchemaValidationError(f"{table_name}[{index}]: row must be an object")
            try:
                validate_record(contract, table_name, record)
            except SchemaValidationError as exc:
                raise SchemaValidationError(f"{table_name}[{index}]: {exc}") from exc

    actors = data["actor"]
    if len({row["region_id"] for row in actors}) < 2:
        raise SchemaValidationError("golden fixture must contain actors in at least two regions")
    if len({row["actor_class"] for row in actors}) < 4:
        raise SchemaValidationError("golden fixture must contain several actor classes")
    if len(data["governance_event"]) < 2:
        raise SchemaValidationError("golden fixture must contain at least two governance events")
    workflow_ids = {row["workflow_instance_id"] for row in data["governance_event"]}
    workflow_event_counts = {
        workflow_id: sum(
            1 for row in data["governance_event"] if row["workflow_instance_id"] == workflow_id
        )
        for workflow_id in workflow_ids
    }
    if max(workflow_event_counts.values()) < 2:
        raise SchemaValidationError(
            "golden fixture must include one workflow with at least two events"
        )
    if not data["event_edge"]:
        raise SchemaValidationError("golden fixture must contain at least one event edge")
    if not data["policy_decision_truth"]:
        raise SchemaValidationError("golden fixture must contain a policy decision")
    if not data["evidence_obligation"] or not data["evidence_receipt"]:
        raise SchemaValidationError(
            "golden fixture must contain evidence obligation and receipt rows"
        )
    if not data["observer_event"]:
        raise SchemaValidationError("golden fixture must contain an observer projection")
    if not data["sample_membership"]:
        raise SchemaValidationError("golden fixture must contain sample membership")

    models = build_model_classes(contract)
    for table_name, rows in data.items():
        model = models[table_name]
        for row in rows:
            model(**row)

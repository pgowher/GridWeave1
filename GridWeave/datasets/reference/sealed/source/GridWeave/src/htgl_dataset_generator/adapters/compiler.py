"""Executable Step 19 adapters, mapping coverage, and conformance evidence."""

from __future__ import annotations

from collections import Counter
import csv
from dataclasses import asdict
from datetime import datetime, timezone
from io import BytesIO, StringIO
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any, Iterable, Mapping, Sequence
import xml.etree.ElementTree as ET
import zipfile

from htgl_dataset_generator._atomic import atomic_replace
from htgl_dataset_generator.observers import ObserverReleaseView
from .models import AdapterBuild, AdapterConformance, AdapterContractError, FieldMapping
from .registry import (
    OBSERVER_PAYLOAD_FIELDS,
    OBSERVER_SCHEMA,
    OBSERVER_TOP_LEVEL_FIELDS,
    REGISTRY_PATH,
    SUPPORTED_ADAPTERS,
    load_adapter_registry,
)


FORBIDDEN_RELEASE_FIELDS = frozenset(
    {
        "anomaly_instance_id",
        "decision_id",
        "event_id",
        "first_order_inclusion_probability",
        "is_violation",
        "obligation_id",
        "protected_pair_id",
        "receipt_id",
        "source_event_id",
        "workflow_instance_id",
    }
)
OBSERVER_ADAPTERS = frozenset({"jsonl_debug_view", "csv", "xes", "jsonld", "sqlite"})
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]+$")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
CIM_NS = "http://iec.ch/TC57/CIM100#"
ATOM_NS = "http://www.w3.org/2005/Atom"
ESPI_NS = "http://naesb.org/espi"
HTGL_XML_NS = "urn:htgl:adapter:extension:1#"


def normalize_canonical_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): normalize_canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [normalize_canonical_value(item) for item in value]
    if isinstance(value, bytes):
        return {"__bytes_hex__": value.hex()}
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise AdapterContractError("adapter timestamps must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AdapterContractError("adapter values cannot contain NaN or infinity")
        return 0.0 if value == 0.0 else value
    return value


def canonical_json_text(value: Any) -> str:
    return json.dumps(
        normalize_canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_json_bytes(value: Any) -> bytes:
    return (canonical_json_text(value) + "\n").encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        atomic_replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def compile_interoperability_adapters(
    views: Mapping[str, ObserverReleaseView],
    tables_by_run: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
    adapters: Iterable[str],
    release_root: Path,
    *,
    csv_max_records_per_view: int = 100_000,
) -> AdapterBuild:
    """Compile configured adapters and fail on undocumented source semantics."""

    configured = tuple(adapters)
    if len(configured) != len(set(configured)):
        raise AdapterContractError("configured adapters cannot contain duplicates")
    if any(item != item.lower() for item in configured):
        raise AdapterContractError("configured adapter IDs must be lowercase")
    unsupported = sorted(set(configured) - SUPPORTED_ADAPTERS)
    if unsupported:
        raise AdapterContractError(f"unsupported interoperability adapters {unsupported}")
    configured = tuple(sorted(configured))
    registry = load_adapter_registry()

    public_views = {
        key: view for key, view in sorted(views.items()) if view.access_class == "public"
    }
    if set(configured) & OBSERVER_ADAPTERS and not public_views:
        raise AdapterContractError(
            "observer interoperability adapters require at least one sanitized public release view"
        )
    observer_records = _validated_public_records(public_views)
    physical = _physical_sources(tables_by_run)

    adapter_root = release_root / "publication" / "adapters"
    data_paths: list[Path] = []
    conformances: list[AdapterConformance] = []
    mapping_rows: list[FieldMapping] = []
    metadata: dict[str, Mapping[str, object]] = {}
    coverage_entries: list[dict[str, Any]] = []

    for adapter_id in configured:
        profile = registry.profile(adapter_id)
        source_records = _profile_source_records(
            adapter_id, observer_records=observer_records, physical=physical
        )
        runtime_fields = _runtime_fields(source_records)
        documented = {
            (mapping.source_schema, mapping.source_field) for mapping in profile.mappings
        }
        undocumented = tuple(sorted(runtime_fields - documented))
        if undocumented:
            raise AdapterContractError(
                f"{adapter_id}: undocumented source fields block conformance: {undocumented}"
            )
        mapping_rows.extend(profile.mappings)
        paths, output_count, round_trip, semantic = _compile_profile(
            adapter_id,
            profile_mappings=profile.mappings,
            public_views=public_views,
            observer_records=observer_records,
            physical=physical,
            adapter_root=adapter_root,
            csv_max_records_per_view=csv_max_records_per_view,
        )
        hashes = tuple(sha256_hex(path.read_bytes()) for path in paths)
        dispositions = Counter(mapping.disposition for mapping in profile.mappings)
        conformance = AdapterConformance(
            adapter_id=adapter_id,
            mapping_profile_id=profile.mapping_profile_id,
            source_record_count=sum(len(rows) for rows in source_records.values()),
            output_record_count=output_count,
            runtime_source_fields=tuple(
                f"{schema}.{field}" for schema, field in sorted(runtime_fields)
            ),
            mapped_field_count=dispositions["mapped"],
            lossy_field_count=dispositions["lossy"],
            unsupported_field_count=dispositions["unsupported"],
            undocumented_field_count=0,
            round_trip_status=round_trip,
            semantic_equivalence_status=semantic,
            output_relative_paths=tuple(
                path.relative_to(release_root).as_posix() for path in paths
            ),
            output_sha256=hashes,
            passed=round_trip.startswith("passed") and semantic.startswith("passed"),
        )
        if not conformance.passed:
            raise AdapterContractError(f"{adapter_id}: executable conformance did not pass")
        conformances.append(conformance)
        data_paths.extend(paths)
        coverage_entries.append(
            {
                "adapter_id": adapter_id,
                "mapping_profile_id": profile.mapping_profile_id,
                "runtime_source_fields": list(conformance.runtime_source_fields),
                "undocumented_fields": [],
                "documented_field_count": len(profile.mappings),
                "runtime_field_count": len(runtime_fields),
            }
        )
        for path in paths:
            relative = path.relative_to(release_root).as_posix()
            restricted = adapter_id in {"cim", "green_button"}
            metadata[relative] = {
                "privacy_class": "restricted" if restricted else "public",
                "generation_stage": "S15_interoperability_adapter",
                "publication_eligible": not restricted,
            }

    control_paths = _write_controls(
        adapter_root,
        registry_sha256=registry.sha256,
        mappings=tuple(mapping_rows),
        conformances=tuple(conformances),
        coverage_entries=coverage_entries,
        configured=configured,
        structural_losses={
            adapter_id: list(registry.profile(adapter_id).structural_losses)
            for adapter_id in configured
        },
    )
    for path in control_paths:
        metadata[path.relative_to(release_root).as_posix()] = {
            "privacy_class": "public",
            "generation_stage": "S15_adapter_conformance",
            "publication_eligible": True,
        }
    all_paths = tuple(sorted(data_paths + list(control_paths)))
    return AdapterBuild(
        registry=registry,
        configured_adapters=configured,
        mappings=tuple(sorted(mapping_rows, key=_mapping_key)),
        conformance=tuple(sorted(conformances, key=lambda item: item.adapter_id)),
        output_paths=all_paths,
        metadata_overrides=dict(sorted(metadata.items())),
    )


def _validated_public_records(
    public_views: Mapping[str, ObserverReleaseView],
) -> tuple[tuple[str, dict[str, Any]], ...]:
    result: list[tuple[str, dict[str, Any]]] = []
    for view_key, view in public_views.items():
        _safe_token(view_key)
        for raw in view.records:
            record = normalize_canonical_value(raw)
            if not isinstance(record, dict) or set(record) != OBSERVER_TOP_LEVEL_FIELDS:
                fields = set(record) if isinstance(record, dict) else set()
                raise AdapterContractError(
                    f"{view_key}: observer release fields mismatch "
                    f"missing={sorted(OBSERVER_TOP_LEVEL_FIELDS-fields)} "
                    f"extra={sorted(fields-OBSERVER_TOP_LEVEL_FIELDS)}"
                )
            payload = record["payload"]
            if not isinstance(payload, dict):
                raise AdapterContractError(f"{view_key}: observer payload must be an object")
            unknown_payload = set(payload) - OBSERVER_PAYLOAD_FIELDS
            if unknown_payload:
                raise AdapterContractError(
                    f"{view_key}: forbidden or undocumented observer payload fields {sorted(unknown_payload)}"
                )
            leaked_names = _recursive_field_names(record) & FORBIDDEN_RELEASE_FIELDS
            if leaked_names:
                raise AdapterContractError(
                    f"{view_key}: evaluator-only field names reached adapter input {sorted(leaked_names)}"
                )
            result.append((view_key, record))
    return tuple(sorted(result, key=lambda item: (item[0], canonical_json_text(item[1]))))


def _physical_sources(
    tables_by_run: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]]
) -> Mapping[tuple[str, int], Mapping[str, tuple[dict[str, Any], ...]]]:
    result: dict[tuple[str, int], Mapping[str, tuple[dict[str, Any], ...]]] = {}
    for key, tables in sorted(tables_by_run.items()):
        selected: dict[str, tuple[dict[str, Any], ...]] = {}
        for table_name in ("network_area", "raw_network_state", "raw_meter_reading"):
            rows = tuple(
                sorted(
                    (normalize_canonical_value(row) for row in tables.get(table_name, ())),
                    key=canonical_json_text,
                )
            )
            selected[table_name] = rows
        result[key] = selected
    return dict(sorted(result.items()))


def _profile_source_records(
    adapter_id: str,
    *,
    observer_records: Sequence[tuple[str, Mapping[str, Any]]],
    physical: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
    if adapter_id in OBSERVER_ADAPTERS:
        return {OBSERVER_SCHEMA: tuple(record for _, record in observer_records)}
    table_names = (
        ("network_area", "raw_network_state")
        if adapter_id == "cim"
        else ("raw_meter_reading",)
    )
    result = {
        table_name: tuple(
            row
            for _, tables in sorted(physical.items())
            for row in tables[table_name]
        )
        for table_name in table_names
    }
    empty = [table_name for table_name, rows in result.items() if not rows]
    if empty:
        raise AdapterContractError(
            f"{adapter_id}: configured physical adapter has no source records for {empty}"
        )
    return result


def _runtime_fields(
    source_records: Mapping[str, Sequence[Mapping[str, Any]]]
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for schema, rows in source_records.items():
        for record in rows:
            for field in record:
                result.add((schema, field))
            if schema == OBSERVER_SCHEMA:
                payload = record["payload"]
                result.update((schema, f"payload.{field}") for field in payload)
    return result


def _compile_profile(
    adapter_id: str,
    *,
    profile_mappings: Sequence[FieldMapping],
    public_views: Mapping[str, ObserverReleaseView],
    observer_records: Sequence[tuple[str, Mapping[str, Any]]],
    physical: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
    adapter_root: Path,
    csv_max_records_per_view: int,
) -> tuple[tuple[Path, ...], int, str, str]:
    if adapter_id == "jsonl_debug_view":
        return _write_jsonl(public_views, adapter_root)
    if adapter_id == "csv":
        return _write_csv(
            public_views,
            adapter_root,
            csv_max_records_per_view,
            profile_mappings,
        )
    if adapter_id == "xes":
        return _write_xes(public_views, adapter_root)
    if adapter_id == "jsonld":
        return _write_jsonld(public_views, adapter_root)
    if adapter_id == "sqlite":
        return _write_sqlite(observer_records, adapter_root)
    if adapter_id == "cim":
        return _write_cim(physical, adapter_root, profile_mappings)
    if adapter_id == "green_button":
        return _write_green_button(physical, adapter_root, profile_mappings)
    raise AdapterContractError(f"no compiler registered for {adapter_id}")


def _write_jsonl(
    views: Mapping[str, ObserverReleaseView], root: Path
) -> tuple[tuple[Path, ...], int, str, str]:
    paths: list[Path] = []
    decoded: list[tuple[str, dict[str, Any]]] = []
    expected: list[tuple[str, dict[str, Any]]] = []
    for key, view in views.items():
        records = _normalized_view_records(view)
        path = root / "jsonl" / _safe_token(key) / "observer_events.jsonl"
        atomic_write_bytes(
            path,
            b"".join((canonical_json_text(row) + "\n").encode("utf-8") for row in records),
        )
        paths.append(path)
        expected.extend((key, row) for row in records)
        decoded.extend(
            (key, json.loads(line))
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        )
    _assert_records_equal("jsonl_debug_view", expected, decoded)
    return tuple(paths), len(expected), "passed_exact_round_trip", "passed_record_equivalence"


def _write_csv(
    views: Mapping[str, ObserverReleaseView],
    root: Path,
    maximum: int,
    mappings: Sequence[FieldMapping],
) -> tuple[tuple[Path, ...], int, str, str]:
    if maximum <= 0:
        raise AdapterContractError("CSV record limit must be positive")
    paths: list[Path] = []
    expected: list[tuple[str, dict[str, Any]]] = []
    decoded: list[tuple[str, dict[str, Any]]] = []
    columns = tuple(sorted(mapping.source_field for mapping in mappings))
    for key, view in views.items():
        records = _normalized_view_records(view)
        if len(records) > maximum:
            raise AdapterContractError(
                f"csv: view {key!r} has {len(records)} records, above small-view limit {maximum}"
            )
        stream = StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\r\n")
        writer.writeheader()
        for row in records:
            writer.writerow(
                {
                    field: canonical_json_text(_field_value_or_none(row, field))
                    for field in columns
                }
            )
        path = root / "csv" / _safe_token(key) / "observer_events.csv"
        atomic_write_bytes(path, stream.getvalue().encode("utf-8"))
        paths.append(path)
        expected.extend((key, row) for row in records)
        reader = csv.DictReader(StringIO(path.read_text(encoding="utf-8"), newline=""))
        if tuple(reader.fieldnames or ()) != columns:
            raise AdapterContractError(f"csv: unstable column contract for {key}")
        for raw in reader:
            values = {field: json.loads(raw[field]) for field in columns}
            for field in (item for item in columns if item.startswith("payload.")):
                if values[field] != _field_value_or_none(values, field):
                    raise AdapterContractError(
                        f"csv: flattened payload column {field!r} disagrees with payload cell"
                    )
            decoded.append(
                (key, {field: values[field] for field in OBSERVER_TOP_LEVEL_FIELDS})
            )
    _assert_records_equal("csv", expected, decoded)
    return tuple(paths), len(expected), "passed_exact_round_trip", "passed_record_equivalence"


def _write_xes(
    views: Mapping[str, ObserverReleaseView], root: Path
) -> tuple[tuple[Path, ...], int, str, str]:
    paths: list[Path] = []
    expected: list[tuple[str, dict[str, Any]]] = []
    decoded: list[tuple[str, dict[str, Any]]] = []
    semantic_expected: list[tuple[str, str, str, str, str]] = []
    semantic_actual: list[tuple[str, str, str, str, str]] = []
    for key, view in views.items():
        records = _normalized_view_records(view)
        log = ET.Element(
            "log",
            {
                "xes.version": "1.0",
                "xes.features": "nested-attributes",
                "xmlns": "http://www.xes-standard.org/",
            },
        )
        for name, prefix, uri in (
            ("Concept", "concept", "http://www.xes-standard.org/concept.xesext"),
            ("Lifecycle", "lifecycle", "http://www.xes-standard.org/lifecycle.xesext"),
            ("Time", "time", "http://www.xes-standard.org/time.xesext"),
            ("Organizational", "org", "http://www.xes-standard.org/org.xesext"),
            ("Identity", "identity", "http://www.xes-standard.org/identity.xesext"),
            ("HTGL", "htgl", "urn:htgl:adapter:xes:1"),
        ):
            ET.SubElement(
                log,
                "extension",
                {"name": name, "prefix": prefix, "uri": uri},
            )
        ET.SubElement(log, "string", {"key": "concept:name", "value": view.profile_id})
        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            workflow = str(record["payload"].get("workflow_ref", record["observer_record_id"]))
            grouped.setdefault(workflow, []).append(record)
        for workflow, items in sorted(grouped.items()):
            trace = ET.SubElement(log, "trace")
            ET.SubElement(trace, "string", {"key": "concept:name", "value": workflow})
            for record in sorted(
                items,
                key=lambda item: (str(item["visible_timestamp"]), str(item["observer_record_id"])),
            ):
                payload = record["payload"]
                event = ET.SubElement(trace, "event")
                ET.SubElement(event, "string", {"key": "concept:name", "value": str(payload.get("event_type", "projected_event"))})
                ET.SubElement(event, "string", {"key": "lifecycle:transition", "value": str(payload.get("workflow_state_after", "unknown"))})
                ET.SubElement(event, "date", {"key": "time:timestamp", "value": str(record["visible_timestamp"])})
                ET.SubElement(event, "string", {"key": "org:resource", "value": str(record["observer_ref"])})
                ET.SubElement(event, "string", {"key": "identity:id", "value": str(payload.get("event_ref", record["observer_record_id"]))})
                ET.SubElement(event, "string", {"key": "htgl:source.record", "value": canonical_json_text(record)})
                for field, value in _flatten_record(record).items():
                    ET.SubElement(event, "string", {"key": f"htgl:source.{field}", "value": canonical_json_text(value)})
                semantic_expected.append(
                    (
                        workflow,
                        str(payload.get("event_type", "projected_event")),
                        str(payload.get("workflow_state_after", "unknown")),
                        str(record["visible_timestamp"]),
                        str(record["observer_ref"]),
                    )
                )
        path = root / "xes" / _safe_token(key) / "observer_events.xes"
        atomic_write_bytes(path, ET.tostring(log, encoding="utf-8", xml_declaration=True, short_empty_elements=True) + b"\n")
        paths.append(path)
        parsed = ET.fromstring(path.read_bytes())
        for trace in _xml_local_children(parsed, "trace"):
            workflow = _xml_attribute_value(trace, "concept:name")
            for event in _xml_local_children(trace, "event"):
                source = json.loads(_xml_attribute_value(event, "htgl:source.record"))
                decoded.append((key, source))
                semantic_actual.append(
                    (
                        workflow,
                        _xml_attribute_value(event, "concept:name"),
                        _xml_attribute_value(event, "lifecycle:transition"),
                        _xml_attribute_value(event, "time:timestamp"),
                        _xml_attribute_value(event, "org:resource"),
                    )
                )
        expected.extend((key, row) for row in records)
    _assert_records_equal("xes", expected, decoded)
    if sorted(semantic_expected) != sorted(semantic_actual):
        raise AdapterContractError("xes: concept/lifecycle/time/organization semantic query mismatch")
    return tuple(paths), len(expected), "passed_exact_extension_round_trip", "passed_xes_query_equivalence"


def _write_jsonld(
    views: Mapping[str, ObserverReleaseView], root: Path
) -> tuple[tuple[Path, ...], int, str, str]:
    paths: list[Path] = []
    expected: list[tuple[str, dict[str, Any]]] = []
    decoded: list[tuple[str, dict[str, Any]]] = []
    semantic_expected: list[tuple[str, str, str]] = []
    semantic_actual: list[tuple[str, str, str]] = []
    context = {
        "prov": "http://www.w3.org/ns/prov#",
        "dpv": "https://w3id.org/dpv#",
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "htgl": "urn:htgl:adapter:semantic:1#",
    }
    for key, view in views.items():
        records = _normalized_view_records(view)
        graph = []
        for record in records:
            payload = record["payload"]
            node = {
                "@id": f"urn:htgl:observer-record:{record['observer_record_id']}",
                "@type": ["prov:Activity", "htgl:ProjectedGovernanceEvent"],
                "prov:generatedAtTime": record["visible_timestamp"],
                "prov:wasAttributedTo": {"@id": f"urn:htgl:observer:{record['observer_ref']}"},
                "prov:wasPartOf": {"@id": f"urn:htgl:workflow:{payload.get('workflow_ref', record['observer_record_id'])}"},
                "prov:wasInformedBy": [
                    {"@id": f"urn:htgl:event:{item}"}
                    for item in payload.get("causal_parent_refs", [])
                ],
                "prov:qualifiedAssociation": [
                    {"prov:agent": {"@type": f"htgl:ActorClass/{item}"}}
                    for item in payload.get("actor_classes", [])
                ],
                "dpv:hasPurpose": payload.get("policy_purpose_id"),
                "dpv:hasProcessing": payload.get("event_family"),
                "dpv:hasPersonalData": payload.get("object_type"),
                "odrl:action": payload.get("event_type"),
                "htgl:projectionProfile": record["projection_profile_id"],
                "htgl:visibilityClass": record["visibility_class"],
                "htgl:redactedFieldPath": record["redacted_field_paths"],
                "htgl:schemaProfile": record["schema_profile_id"],
                "htgl:eventRef": payload.get("event_ref"),
                "htgl:databaseKind": payload.get("database_kind"),
                "htgl:evidencePresent": payload.get("evidence_present"),
                "htgl:evidenceReceiptCount": payload.get("evidence_receipt_count"),
                "htgl:evidenceType": payload.get("evidence_types"),
                "htgl:inferredSummary": payload.get("inferred_summary"),
                "htgl:stateBefore": payload.get("workflow_state_before"),
                "htgl:stateAfter": payload.get("workflow_state_after"),
                "htgl:workflowRef": payload.get(
                    "workflow_ref", record["observer_record_id"]
                ),
                "htgl:projectionDigest": record["projection_digest"],
                "htgl:source": record,
            }
            graph.append(node)
            semantic_expected.append(
                (str(payload.get("workflow_ref", record["observer_record_id"])), str(payload.get("event_type")), str(payload.get("policy_purpose_id")))
            )
        document = {
            "@context": context,
            "@id": f"urn:htgl:observer-profile:{view.profile_id}",
            "@type": "prov:Bundle",
            "@graph": graph,
        }
        path = root / "prov_dpv_odrl" / _safe_token(key) / "observer_events.jsonld"
        atomic_write_bytes(path, canonical_json_bytes(document))
        paths.append(path)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        for node in parsed["@graph"]:
            decoded.append((key, node["htgl:source"]))
            semantic_actual.append(
                (
                    str(node["htgl:workflowRef"]),
                    str(node["odrl:action"]),
                    str(node["dpv:hasPurpose"]),
                )
            )
        expected.extend((key, row) for row in records)
    _assert_records_equal("jsonld", expected, decoded)
    if sorted(semantic_expected) != sorted(semantic_actual):
        raise AdapterContractError("jsonld: PROV/DPV/ODRL semantic query mismatch")
    return tuple(paths), len(expected), "passed_exact_extension_round_trip", "passed_semantic_query_equivalence"


def _write_sqlite(
    records: Sequence[tuple[str, Mapping[str, Any]]], root: Path
) -> tuple[tuple[Path, ...], int, str, str]:
    with tempfile.TemporaryDirectory(prefix="htgl-sqlite-adapter-") as temporary:
        database_path = Path(temporary) / "observer_index.sqlite"
        connection = sqlite3.connect(database_path)
        try:
            connection.executescript(
                """
                PRAGMA page_size=4096;
                PRAGMA auto_vacuum=NONE;
                PRAGMA journal_mode=OFF;
                PRAGMA synchronous=OFF;
                PRAGMA temp_store=MEMORY;
                PRAGMA application_id=1213482828;
                PRAGMA user_version=1;
                CREATE TABLE observer_event (
                    view_key TEXT NOT NULL,
                    observer_record_id TEXT NOT NULL,
                    projection_profile_id TEXT NOT NULL,
                    visible_timestamp TEXT NOT NULL,
                    visibility_class TEXT NOT NULL,
                    workflow_ref TEXT,
                    event_family TEXT,
                    event_type TEXT,
                    policy_purpose_id TEXT,
                    projection_digest TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (view_key, observer_record_id)
                ) WITHOUT ROWID;
                """
            )
            for view_key, record in records:
                payload = record["payload"]
                connection.execute(
                    "INSERT INTO observer_event VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        view_key,
                        str(record["observer_record_id"]),
                        str(record["projection_profile_id"]),
                        str(record["visible_timestamp"]),
                        str(record["visibility_class"]),
                        _optional_text(payload.get("workflow_ref")),
                        _optional_text(payload.get("event_family")),
                        _optional_text(payload.get("event_type")),
                        _optional_text(payload.get("policy_purpose_id")),
                        str(record["projection_digest"]),
                        canonical_json_text(record),
                    ),
                )
            connection.executescript(
                """
                CREATE INDEX observer_event_workflow_idx ON observer_event(workflow_ref, visible_timestamp);
                CREATE INDEX observer_event_type_idx ON observer_event(event_family, event_type);
                CREATE INDEX observer_event_purpose_idx ON observer_event(policy_purpose_id);
                ANALYZE;
                VACUUM;
                """
            )
            connection.commit()
            actual = tuple(
                (row[0], json.loads(row[1]))
                for row in connection.execute(
                    "SELECT view_key, record_json FROM observer_event ORDER BY view_key, observer_record_id"
                )
            )
            query_count = int(connection.execute("SELECT COUNT(*) FROM observer_event").fetchone()[0])
        finally:
            connection.close()
        _assert_records_equal("sqlite", records, actual)
        if query_count != len(records):
            raise AdapterContractError("sqlite: indexed row-count query mismatch")
        archive = _deterministic_zip(
            {
                "observer_index.sqlite": database_path.read_bytes(),
                "README.json": canonical_json_bytes(
                    {
                        "format": "htgl.sqlite.public-observer-index.v1",
                        "authoritative": False,
                        "source": "sanitized_public_observer_release_only",
                        "record_count": len(records),
                    }
                ),
            }
        )
    path = root / "sqlite" / "public_observer_index.zip"
    atomic_write_bytes(path, archive)
    return (path,), len(records), "passed_exact_record_round_trip", "passed_sql_query_equivalence"


def _write_cim(
    physical: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
    root: Path,
    mappings: Sequence[FieldMapping],
) -> tuple[tuple[Path, ...], int, str, str]:
    paths: list[Path] = []
    count = 0
    for (scenario_id, replicate_id), tables in sorted(physical.items()):
        records = [
            (schema, row)
            for schema in ("network_area", "raw_network_state")
            for row in tables[schema]
        ]
        if not records:
            continue
        ET.register_namespace("rdf", RDF_NS)
        ET.register_namespace("cim", CIM_NS)
        ET.register_namespace("htgl", HTGL_XML_NS)
        document = ET.Element(_qname(RDF_NS, "RDF"))
        for schema, record in records:
            if schema == "network_area":
                resource_id = str(record["network_area_id"])
                resource = ET.SubElement(
                    document,
                    _qname(CIM_NS, "SubGeographicalRegion"),
                    {_qname(RDF_NS, "about"): f"urn:htgl:network-area:{resource_id}"},
                )
                ET.SubElement(resource, _qname(CIM_NS, "IdentifiedObject.mRID")).text = resource_id
                ET.SubElement(resource, _qname(CIM_NS, "IdentifiedObject.name")).text = str(record["network_area_kind"])
                if record.get("parent_network_area_id") is not None:
                    ET.SubElement(
                        resource,
                        _qname(CIM_NS, "SubGeographicalRegion.Region"),
                        {
                            _qname(RDF_NS, "resource"): (
                                f"urn:htgl:network-area:{record['parent_network_area_id']}"
                            )
                        },
                    )
            else:
                resource_id = str(record["network_state_id"])
                resource = ET.SubElement(
                    document,
                    _qname(CIM_NS, "AnalogValue"),
                    {_qname(RDF_NS, "about"): f"urn:htgl:network-state:{resource_id}"},
                )
                ET.SubElement(resource, _qname(CIM_NS, "IdentifiedObject.mRID")).text = resource_id
                ET.SubElement(
                    resource,
                    _qname(CIM_NS, "MeasurementValue.timeStamp"),
                ).text = str(record["timestamp"])
                if record.get("active_power_kw") is not None:
                    ET.SubElement(
                        resource, _qname(CIM_NS, "AnalogValue.value")
                    ).text = canonical_json_text(record["active_power_kw"])
                ET.SubElement(
                    resource,
                    _qname(CIM_NS, "MeasurementValue.MeasurementValueSource"),
                    {_qname(RDF_NS, "resource"): f"urn:htgl:solver:{record['solver_backend']}"},
                )
            element = ET.SubElement(
                resource,
                _qname(HTGL_XML_NS, "HTGLRecord"),
                {"sourceSchema": schema},
            )
            ET.SubElement(element, _qname(HTGL_XML_NS, "SourceJSON")).text = canonical_json_text(record)
            for mapping in (item for item in mappings if item.source_schema == schema):
                ET.SubElement(
                    element,
                    _qname(HTGL_XML_NS, "MappedValue"),
                    {"target": str(mapping.target_field), "source": mapping.source_field},
                ).text = canonical_json_text(_field_value(record, mapping.source_field))
        xml_bytes = ET.tostring(document, encoding="utf-8", xml_declaration=True, short_empty_elements=True) + b"\n"
        decoded = _verify_mapped_xml_records(
            xml_bytes,
            record_element="HTGLRecord",
            mappings=mappings,
            fixed_source_schema=None,
        )
        expected = [record for _, record in records]
        if _canonical_multiset(decoded) != _canonical_multiset(expected):
            raise AdapterContractError("cim: extension round-trip mismatch")
        native_ids = {
            str(item.text)
            for item in ET.fromstring(xml_bytes).iter()
            if _local_name(item.tag) == "IdentifiedObject.mRID"
        }
        expected_ids = {
            str(record["network_area_id"] if schema == "network_area" else record["network_state_id"])
            for schema, record in records
        }
        if native_ids != expected_ids:
            raise AdapterContractError("cim: native mRID query does not cover source records")
        profile = {
            "format": "htgl.cim-network-measurement.v1",
            "standard": "IEC 61970-301:2020 aligned",
            "certification_claim": False,
            "source_schemas": ["network_area", "raw_network_state"],
            "record_count": len(records),
        }
        path = root / "cim" / _safe_token(scenario_id) / f"replicate-{replicate_id}" / "cim_profile.zip"
        atomic_write_bytes(path, _deterministic_zip({"cim.xml": xml_bytes, "profile.json": canonical_json_bytes(profile)}))
        paths.append(path)
        count += len(records)
    if not paths:
        raise AdapterContractError("cim: no physical records were compiled")
    return tuple(paths), count, "passed_exact_extension_round_trip", "passed_cim_mapped_value_equivalence"


def _write_green_button(
    physical: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
    root: Path,
    mappings: Sequence[FieldMapping],
) -> tuple[tuple[Path, ...], int, str, str]:
    paths: list[Path] = []
    count = 0
    for (scenario_id, replicate_id), tables in sorted(physical.items()):
        records = list(tables["raw_meter_reading"])
        if not records:
            continue
        ET.register_namespace("", ATOM_NS)
        ET.register_namespace("espi", ESPI_NS)
        ET.register_namespace("htgl", HTGL_XML_NS)
        feed = ET.Element(_qname(ATOM_NS, "feed"))
        ET.SubElement(feed, _qname(ATOM_NS, "id")).text = (
            f"urn:htgl:green-button:{scenario_id}:replicate:{replicate_id}"
        )
        ET.SubElement(feed, _qname(ATOM_NS, "title")).text = (
            "HTGL synthetic interval-reading exchange"
        )
        ET.SubElement(feed, _qname(ATOM_NS, "updated")).text = max(
            str(record["interval_end"]) for record in records
        )
        for record in records:
            entry = ET.SubElement(feed, _qname(ATOM_NS, "entry"))
            ET.SubElement(entry, _qname(ATOM_NS, "id")).text = (
                f"urn:htgl:interval-reading:{record['reading_id']}"
            )
            ET.SubElement(entry, _qname(ATOM_NS, "title")).text = "Synthetic IntervalReading"
            ET.SubElement(entry, _qname(ATOM_NS, "updated")).text = str(record["interval_end"])
            content = ET.SubElement(
                entry, _qname(ATOM_NS, "content"), {"type": "application/xml"}
            )
            interval = ET.SubElement(content, _qname(ESPI_NS, "IntervalReading"))
            time_period = ET.SubElement(interval, _qname(ESPI_NS, "timePeriod"))
            start = _parse_timestamp(str(record["interval_start"]))
            end = _parse_timestamp(str(record["interval_end"]))
            ET.SubElement(time_period, _qname(ESPI_NS, "start")).text = str(
                int(start.timestamp())
            )
            ET.SubElement(time_period, _qname(ESPI_NS, "duration")).text = str(
                int((end - start).total_seconds())
            )
            ET.SubElement(interval, _qname(ESPI_NS, "value")).text = canonical_json_text(
                record["import_energy_kwh"]
            )
            for quality in record["quality_flags"]:
                ET.SubElement(
                    interval, _qname(ESPI_NS, "ReadingQuality")
                ).text = str(quality)
            control = ET.SubElement(interval, _qname(HTGL_XML_NS, "HTGLRecord"))
            ET.SubElement(control, _qname(HTGL_XML_NS, "SourceJSON")).text = canonical_json_text(record)
            for mapping in mappings:
                ET.SubElement(
                    control,
                    _qname(HTGL_XML_NS, "MappedValue"),
                    {"target": str(mapping.target_field), "source": mapping.source_field},
                ).text = canonical_json_text(_field_value(record, mapping.source_field))
        xml_bytes = ET.tostring(feed, encoding="utf-8", xml_declaration=True, short_empty_elements=True) + b"\n"
        decoded = _verify_mapped_xml_records(
            xml_bytes,
            record_element="HTGLRecord",
            mappings=mappings,
            fixed_source_schema="raw_meter_reading",
        )
        if _canonical_multiset(decoded) != _canonical_multiset(records):
            raise AdapterContractError("green_button: extension round-trip mismatch")
        native_entries = [
            item
            for item in ET.fromstring(xml_bytes).iter()
            if _local_name(item.tag) == "IntervalReading"
        ]
        if len(native_entries) != len(records):
            raise AdapterContractError(
                "green_button: native IntervalReading query does not cover source records"
            )
        profile = {
            "format": "htgl.green-button-interval-reading.v1",
            "standard": "NAESB REQ.21 ESPI aligned",
            "certification_claim": False,
            "customer_authorization_claim": False,
            "source_schema": "raw_meter_reading",
            "record_count": len(records),
        }
        path = root / "green_button" / _safe_token(scenario_id) / f"replicate-{replicate_id}" / "green_button_profile.zip"
        atomic_write_bytes(path, _deterministic_zip({"feed.xml": xml_bytes, "profile.json": canonical_json_bytes(profile)}))
        paths.append(path)
        count += len(records)
    if not paths:
        raise AdapterContractError("green_button: no interval-reading records were compiled")
    return tuple(paths), count, "passed_exact_extension_round_trip", "passed_interval_query_equivalence"


def _write_controls(
    adapter_root: Path,
    *,
    registry_sha256: str,
    mappings: Sequence[FieldMapping],
    conformances: Sequence[AdapterConformance],
    coverage_entries: Sequence[Mapping[str, Any]],
    configured: Sequence[str],
    structural_losses: Mapping[str, Sequence[str]],
) -> tuple[Path, ...]:
    mapping_path = adapter_root / "mapping" / "field_mapping.parquet"
    _write_mapping_parquet(mapping_path, mappings, registry_sha256)
    registry_path = adapter_root / "mapping" / "mapping_registry.json"
    atomic_write_bytes(
        registry_path,
        canonical_json_bytes(json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))),
    )
    conformance_path = adapter_root / "conformance.json"
    atomic_write_bytes(
        conformance_path,
        canonical_json_bytes(
            {
                "format": "htgl.adapter-conformance.v1",
                "mapping_registry_sha256": registry_sha256,
                "configured_adapters": list(configured),
                "all_passed": all(item.passed for item in conformances),
                "entries": [asdict(item) for item in conformances],
                "authoritative_storage": "typed_arrow_parquet_zstd",
                "adapters_are_authoritative": False,
            }
        ),
    )
    unmapped_path = adapter_root / "unmapped_fields.json"
    atomic_write_bytes(
        unmapped_path,
        canonical_json_bytes(
            {
                "format": "htgl.adapter-unmapped-fields.v1",
                "mapping_registry_sha256": registry_sha256,
                "undocumented_field_count": 0,
                "entries": list(coverage_entries),
                "conformance_blocking_rule": "any undocumented source field blocks adapter conformance",
            }
        ),
    )
    loss_path = adapter_root / "loss_report.json"
    atomic_write_bytes(
        loss_path,
        canonical_json_bytes(
            {
                "format": "htgl.adapter-loss-report.v1",
                "mapping_registry_sha256": registry_sha256,
                "entries": [
                    {
                        "adapter_id": item.adapter_id,
                        "mapping_profile_id": item.mapping_profile_id,
                        "structural_losses": list(structural_losses[item.adapter_id]),
                        "mapped_field_count": item.mapped_field_count,
                        "lossy_field_count": item.lossy_field_count,
                        "unsupported_field_count": item.unsupported_field_count,
                        "undocumented_field_count": item.undocumented_field_count,
                    }
                    for item in conformances
                ],
                "claim_boundary": (
                    "Adapters are projections of canonical benchmark artifacts. They do not establish "
                    "legal compliance, real deletion, Green Button or IEC certification, ledger anchoring, "
                    "utility deployment, or operational HTGL execution."
                ),
            }
        ),
    )
    return tuple(sorted((mapping_path, registry_path, conformance_path, unmapped_path, loss_path)))


def _write_mapping_parquet(
    path: Path, mappings: Sequence[FieldMapping], registry_sha256: str
) -> None:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise AdapterContractError("pyarrow is required for the adapter mapping table") from exc
    fields = [
        pa.field("adapter_id", pa.string(), nullable=False),
        pa.field("mapping_profile_id", pa.string(), nullable=False),
        pa.field("profile_version", pa.string(), nullable=False),
        pa.field("target_standard", pa.string(), nullable=False),
        pa.field("target_standard_version", pa.string(), nullable=False),
        pa.field("source_schema", pa.string(), nullable=False),
        pa.field("source_field", pa.string(), nullable=False),
        pa.field("target_field", pa.string(), nullable=True),
        pa.field("cardinality", pa.string(), nullable=False),
        pa.field("transformation", pa.string(), nullable=False),
        pa.field("vocabulary_conversion", pa.string(), nullable=True),
        pa.field("disposition", pa.string(), nullable=False),
        pa.field("rationale", pa.string(), nullable=False),
        pa.field("mapping_registry_sha256", pa.string(), nullable=False),
    ]
    base = pa.schema(fields)
    fingerprint = hashlib.sha256(base.serialize().to_pybytes()).hexdigest()
    schema = base.with_metadata(
        {
            b"htgl.schema_id": b"htgl.adapter.field-mapping.v1",
            b"htgl.schema_version": b"1.0.0",
            b"htgl.schema_fingerprint": fingerprint.encode("ascii"),
            b"htgl.privacy_class": b"public",
            b"htgl.compression": b"ZSTD",
            b"htgl.mapping_registry_sha256": registry_sha256.encode("ascii"),
        }
    )
    rows = [
        {**asdict(mapping), "mapping_registry_sha256": registry_sha256}
        for mapping in sorted(mappings, key=_mapping_key)
    ]
    table = pa.Table.from_pylist(rows, schema=schema)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        pq.write_table(
            table,
            temporary,
            compression="ZSTD",
            compression_level=9,
            version="2.6",
            data_page_version="1.0",
            use_dictionary=True,
            write_statistics=True,
            use_compliant_nested_type=True,
        )
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        atomic_replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _normalized_view_records(view: ObserverReleaseView) -> list[dict[str, Any]]:
    return sorted(
        (normalize_canonical_value(record) for record in view.records),
        key=canonical_json_text,
    )


def _flatten_record(record: Mapping[str, Any]) -> Mapping[str, Any]:
    result = {field: value for field, value in record.items() if field != "payload"}
    result["payload"] = record["payload"]
    result.update({f"payload.{field}": value for field, value in record["payload"].items()})
    return dict(sorted(result.items()))


def _field_value(record: Mapping[str, Any], path: str) -> Any:
    current: Any = record
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            raise AdapterContractError(f"source path {path!r} is unavailable")
        current = current[segment]
    return current


def _field_value_or_none(record: Mapping[str, Any], path: str) -> Any:
    try:
        return _field_value(record, path)
    except AdapterContractError:
        return None


def _assert_records_equal(
    adapter_id: str,
    expected: Sequence[tuple[str, Mapping[str, Any]]],
    actual: Sequence[tuple[str, Mapping[str, Any]]],
) -> None:
    expected_values = Counter(
        (key, canonical_json_text(record)) for key, record in expected
    )
    actual_values = Counter((key, canonical_json_text(record)) for key, record in actual)
    if expected_values != actual_values:
        raise AdapterContractError(f"{adapter_id}: round-trip record multiset mismatch")


def _canonical_multiset(records: Sequence[Mapping[str, Any]]) -> Counter[str]:
    return Counter(canonical_json_text(record) for record in records)


def _recursive_field_names(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return set(str(key) for key in value) | {
            name for item in value.values() for name in _recursive_field_names(item)
        }
    if isinstance(value, list):
        return {name for item in value for name in _recursive_field_names(item)}
    return set()


def _xml_local_children(parent: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in parent if _local_name(child.tag) == name]


def _xml_attribute_value(parent: ET.Element, key: str) -> str:
    for child in parent:
        if child.attrib.get("key") == key:
            return child.attrib["value"]
    raise AdapterContractError(f"XES element lacks required attribute {key!r}")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _qname(namespace: str, local_name: str) -> str:
    return f"{{{namespace}}}{local_name}"


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AdapterContractError(f"timestamp is not timezone-aware: {value!r}")
    return parsed.astimezone(timezone.utc)


def _verify_mapped_xml_records(
    payload: bytes,
    *,
    record_element: str,
    mappings: Sequence[FieldMapping],
    fixed_source_schema: str | None,
) -> list[Mapping[str, Any]]:
    root = ET.fromstring(payload)
    by_schema: dict[str, dict[str, FieldMapping]] = {}
    for mapping in mappings:
        by_schema.setdefault(mapping.source_schema, {})[mapping.source_field] = mapping
    records: list[Mapping[str, Any]] = []
    for element in root.iter():
        if _local_name(element.tag) != record_element:
            continue
        schema = fixed_source_schema or element.attrib.get("sourceSchema")
        if schema not in by_schema:
            raise AdapterContractError(
                f"XML adapter record has unknown source schema {schema!r}"
            )
        source_nodes = [
            child for child in element if _local_name(child.tag) == "SourceJSON"
        ]
        if len(source_nodes) != 1:
            raise AdapterContractError("XML adapter record must contain one SourceJSON")
        record = json.loads(source_nodes[0].text or "null")
        mapped_nodes = [
            child for child in element if _local_name(child.tag) == "MappedValue"
        ]
        actual_fields = {child.attrib.get("source") for child in mapped_nodes}
        expected_fields = set(by_schema[schema])
        if actual_fields != expected_fields or len(mapped_nodes) != len(expected_fields):
            raise AdapterContractError(
                f"XML adapter mapped-field coverage mismatch for {schema}"
            )
        for child in mapped_nodes:
            source_field = str(child.attrib["source"])
            mapping = by_schema[schema][source_field]
            if child.attrib.get("target") != mapping.target_field:
                raise AdapterContractError(
                    f"XML adapter target mismatch for {schema}.{source_field}"
                )
            if json.loads(child.text or "null") != _field_value(record, source_field):
                raise AdapterContractError(
                    f"XML adapter value mismatch for {schema}.{source_field}"
                )
        records.append(record)
    return records


def _deterministic_zip(files: Mapping[str, bytes]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(
        stream, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, payload in sorted(files.items()):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.flag_bits |= 0x800
            archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return stream.getvalue()


def _safe_token(value: str) -> str:
    if not SAFE_TOKEN.fullmatch(value):
        raise AdapterContractError(f"unsafe adapter path token {value!r}")
    return value.replace(":", "__")


def _optional_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _mapping_key(mapping: FieldMapping) -> tuple[str, str, str]:
    return mapping.adapter_id, mapping.source_schema, mapping.source_field

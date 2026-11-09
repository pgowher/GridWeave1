"""Schema-bound Arrow/Parquet writers.

The writer intentionally requires ``pyarrow``. If the dependency is missing, it
fails with an explicit error instead of writing JSON or another compatibility
format under a Parquet filename.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import heapq
from itertools import chain, islice
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence
import json
import math
import os
import re
import tempfile

from htgl_dataset_generator._atomic import atomic_replace
from htgl_dataset_generator.schemas import ContractSpec, FieldSpec, TableSpec, load_contract, validate_record


FIXED_SIZE_BINARY_RE = re.compile(r"^fixed_size_binary\[(\d+)\]$")
LIST_RE = re.compile(r"^list<(.+)>$")
DEFAULT_MAXIMUM_BUFFERED_ROWS = 50_000
ROW_GROUP_SAMPLE_ROWS = 1_024


class ParquetDependencyError(RuntimeError):
    """Raised when pyarrow is not installed for authoritative Parquet writing."""


class ParquetWriteError(RuntimeError):
    """Raised when schema-bound Parquet writing fails."""


@dataclass(frozen=True)
class ParquetWriteReport:
    path: Path
    table_name: str
    record_count: int
    stored_bytes: int
    uncompressed_bytes: int
    row_group_count: int
    row_group_uncompressed_bytes: tuple[int, ...]
    row_group_target_bytes: int | None
    row_group_efficiency: float | None
    schema_id: str
    schema_fingerprint: str
    sha256: str
    external_sort_spill_count: int
    maximum_rows_in_memory: int


@dataclass(frozen=True)
class _PreparedRows:
    rows: Iterator[dict[str, Any]]
    spill_count: int
    peak_sort_buffer_rows: int


def _require_pyarrow() -> tuple[Any, Any]:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ModuleNotFoundError as exc:
        raise ParquetDependencyError(
            "pyarrow is required for authoritative Parquet/ZSTD output. "
            "Install the project dependencies from pyproject.toml before writing artifacts."
        ) from exc
    return pa, pq


def _arrow_type(pa: Any, logical_type: str) -> Any:
    list_match = LIST_RE.match(logical_type)
    if list_match:
        return pa.list_(_arrow_type(pa, list_match.group(1)))
    if logical_type in {"string", "large_string"}:
        return pa.string()
    if logical_type == "dictionary<string>":
        return pa.dictionary(pa.int32(), pa.string())
    if logical_type == "int32":
        return pa.int32()
    if logical_type == "int64":
        return pa.int64()
    if logical_type == "float32":
        return pa.float32()
    if logical_type == "float64":
        return pa.float64()
    if logical_type == "bool":
        return pa.bool_()
    if logical_type == "timestamp[us, UTC]":
        return pa.timestamp("us", tz="UTC")
    fixed = FIXED_SIZE_BINARY_RE.match(logical_type)
    if fixed is not None:
        return pa.binary(int(fixed.group(1)))
    raise ParquetWriteError(f"unsupported Arrow logical type {logical_type!r}")


def arrow_schema_for_table(table: TableSpec) -> Any:
    """Return a ``pyarrow.Schema`` matching the locked table contract."""

    pa, _ = _require_pyarrow()
    fields = []
    for field_spec in table.fields:
        metadata = {
            "dictionary_source": field_spec.dictionary_source or "",
            "privacy_class": field_spec.privacy_class,
            "semantic_invariant": field_spec.semantic_invariant,
        }
        fields.append(
            pa.field(
                field_spec.name,
                _arrow_type(pa, field_spec.logical_type),
                nullable=field_spec.nullable,
                metadata={key.encode("utf-8"): value.encode("utf-8") for key, value in metadata.items()},
            )
        )
    schema_metadata = {
        "schema_id": table.schema_id,
        "schema_version": table.schema_version,
        "schema_fingerprint": table.schema_fingerprint,
        "table_name": table.table_name,
    }
    return pa.schema(
        fields,
        metadata={key.encode("utf-8"): value.encode("utf-8") for key, value in schema_metadata.items()},
    )


def _normalize_timestamp(value: Any) -> Any:
    if value is None:
        return None
    parsed = value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(parsed, datetime):
        return parsed
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ParquetWriteError("timestamp values must be timezone-aware")
    return parsed.astimezone(timezone.utc).replace(tzinfo=timezone.utc)


def _normalize_value(field_spec: FieldSpec, value: Any) -> Any:
    if value is None:
        return None
    list_match = LIST_RE.match(field_spec.logical_type)
    if list_match:
        inner = FieldSpec(
            name=field_spec.name,
            logical_type=list_match.group(1),
            nullable=False,
            dictionary_source=field_spec.dictionary_source,
            privacy_class=field_spec.privacy_class,
            description=field_spec.description,
            semantic_invariant=field_spec.semantic_invariant,
        )
        return [_normalize_value(inner, item) for item in value]
    if field_spec.logical_type == "timestamp[us, UTC]":
        return _normalize_timestamp(value)
    if field_spec.logical_type in {"float32", "float64"}:
        normalized = float(value)
        if not math.isfinite(normalized):
            raise ParquetWriteError(
                f"{field_spec.name}: non-finite floating-point values are forbidden"
            )
        return 0.0 if normalized == 0.0 else normalized
    fixed = FIXED_SIZE_BINARY_RE.match(field_spec.logical_type)
    if fixed is not None and isinstance(value, str):
        return bytes.fromhex(value)
    return value


def _canonical_sort_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds")
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_sort_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_sort_value(item) for item in value]
    return value


def _canonical_row_key(row: Mapping[str, Any]) -> str:
    return json.dumps(
        _canonical_sort_value(row),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _normalize_record(
    table: TableSpec,
    record: Mapping[str, Any],
    contract: ContractSpec,
    *,
    index: int,
) -> dict[str, Any]:
    try:
        validate_record(contract, table.table_name, record)
        return {
            field_spec.name: _normalize_value(field_spec, record[field_spec.name])
            for field_spec in table.fields
        }
    except Exception as exc:
        raise ParquetWriteError(
            f"{table.table_name}[{index}]: cannot write invalid record: {exc}"
        ) from exc


def _iter_parquet_rows(pq: Any, path: Path) -> Iterator[dict[str, Any]]:
    parquet_file = pq.ParquetFile(path)
    for batch in parquet_file.iter_batches(batch_size=4_096):
        yield from batch.to_pylist()


def _prepare_rows(
    *,
    pa: Any,
    pq: Any,
    schema: Any,
    table: TableSpec,
    records: Iterable[Mapping[str, Any]],
    contract: ContractSpec,
    canonical_sort: bool,
    maximum_buffered_rows: int,
    spill_dir: Path,
) -> _PreparedRows:
    if maximum_buffered_rows < 1:
        raise ParquetWriteError("maximum_buffered_rows must be positive")

    if not canonical_sort:
        def normalized() -> Iterator[dict[str, Any]]:
            for index, record in enumerate(records):
                yield _normalize_record(table, record, contract, index=index)

        return _PreparedRows(
            rows=normalized(),
            spill_count=0,
            peak_sort_buffer_rows=0,
        )

    spill_paths: list[Path] = []
    buffer: list[dict[str, Any]] = []
    peak = 0
    for index, record in enumerate(records):
        buffer.append(_normalize_record(table, record, contract, index=index))
        peak = max(peak, len(buffer))
        if len(buffer) < maximum_buffered_rows:
            continue
        buffer.sort(key=_canonical_row_key)
        spill_path = spill_dir / f"sort-{len(spill_paths):08d}.parquet"
        pq.write_table(
            pa.Table.from_pylist(buffer, schema=schema),
            spill_path,
            compression="NONE",
            version="2.6",
            data_page_version="1.0",
            use_dictionary=False,
            write_statistics=False,
            use_compliant_nested_type=True,
            row_group_size=maximum_buffered_rows,
        )
        spill_paths.append(spill_path)
        buffer = []

    buffer.sort(key=_canonical_row_key)
    if not spill_paths:
        return _PreparedRows(rows=iter(buffer), spill_count=0, peak_sort_buffer_rows=peak)

    iterators: list[Iterator[dict[str, Any]]] = [
        _iter_parquet_rows(pq, path) for path in spill_paths
    ]
    if buffer:
        iterators.append(iter(buffer))
    return _PreparedRows(
        rows=heapq.merge(*iterators, key=_canonical_row_key),
        spill_count=len(spill_paths),
        peak_sort_buffer_rows=peak,
    )


def _row_group_rows(
    pa: Any,
    schema: Any,
    sample_rows: Sequence[Mapping[str, Any]],
    *,
    target_bytes: int | None,
    maximum_buffered_rows: int,
) -> int:
    if target_bytes is not None and target_bytes <= 0:
        raise ParquetWriteError("row_group_target_bytes must be positive")
    if not sample_rows:
        return 1
    if target_bytes is None:
        return maximum_buffered_rows
    sample = pa.Table.from_pylist(sample_rows, schema=schema)
    approximate_bytes_per_row = max(1.0, float(sample.nbytes) / len(sample_rows))
    return max(1, min(maximum_buffered_rows, int(target_bytes / approximate_bytes_per_row)))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inspect_parquet(
    *,
    pq: Any,
    path: Path,
    table: TableSpec,
    record_count: int,
    row_group_target_bytes: int | None,
    spill_count: int,
    maximum_rows_in_memory: int,
) -> ParquetWriteReport:
    parquet_file = pq.ParquetFile(path)
    metadata = parquet_file.metadata
    row_group_bytes = tuple(
        int(metadata.row_group(index).total_byte_size)
        for index in range(metadata.num_row_groups)
    )
    if row_group_target_bytes is None or not row_group_bytes:
        efficiency = None
    else:
        capacity = row_group_target_bytes * len(row_group_bytes)
        efficiency = sum(min(value, row_group_target_bytes) for value in row_group_bytes) / capacity
    return ParquetWriteReport(
        path=path,
        table_name=table.table_name,
        record_count=record_count,
        stored_bytes=path.stat().st_size,
        uncompressed_bytes=sum(row_group_bytes),
        row_group_count=len(row_group_bytes),
        row_group_uncompressed_bytes=row_group_bytes,
        row_group_target_bytes=row_group_target_bytes,
        row_group_efficiency=efficiency,
        schema_id=table.schema_id,
        schema_fingerprint=table.schema_fingerprint,
        sha256=_sha256_file(path),
        external_sort_spill_count=spill_count,
        maximum_rows_in_memory=maximum_rows_in_memory,
    )


def write_parquet_table(
    table_name: str,
    records: Iterable[Mapping[str, Any]],
    output_path: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
    compression: str = "ZSTD",
    compression_level: int = 9,
    canonical_sort: bool = True,
    row_group_target_bytes: int | None = None,
    maximum_buffered_rows: int = DEFAULT_MAXIMUM_BUFFERED_ROWS,
) -> Path:
    """Write one contract-bound table to Parquet atomically and deterministically."""

    return write_parquet_table_with_report(
        table_name,
        records,
        output_path,
        contract=contract,
        compression=compression,
        compression_level=compression_level,
        canonical_sort=canonical_sort,
        row_group_target_bytes=row_group_target_bytes,
        maximum_buffered_rows=maximum_buffered_rows,
    ).path


def write_parquet_table_with_report(
    table_name: str,
    records: Iterable[Mapping[str, Any]],
    output_path: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
    compression: str = "ZSTD",
    compression_level: int = 9,
    canonical_sort: bool = True,
    row_group_target_bytes: int | None = None,
    maximum_buffered_rows: int = DEFAULT_MAXIMUM_BUFFERED_ROWS,
) -> ParquetWriteReport:
    """Stream one contract table through bounded sorting and Parquet row groups.

    Canonical sorting uses deterministic spill files when the declared row
    buffer is exhausted. Spill files are working state only and never become
    authoritative artifacts.
    """

    schema_contract = contract if contract is not None else load_contract()
    table = schema_contract.table(table_name)
    pa, pq = _require_pyarrow()
    schema = arrow_schema_for_table(table)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=str(output.parent),
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
    try:
        with tempfile.TemporaryDirectory(
            prefix=".s-",
            dir=str(output.parent),
        ) as spill_root:
            prepared = _prepare_rows(
                pa=pa,
                pq=pq,
                schema=schema,
                table=table,
                records=records,
                contract=schema_contract,
                canonical_sort=canonical_sort,
                maximum_buffered_rows=maximum_buffered_rows,
                spill_dir=Path(spill_root),
            )
            iterator = iter(prepared.rows)
            sample_rows = list(islice(iterator, min(ROW_GROUP_SAMPLE_ROWS, maximum_buffered_rows)))
            row_group_rows = _row_group_rows(
                pa,
                schema,
                sample_rows,
                target_bytes=row_group_target_bytes,
                maximum_buffered_rows=maximum_buffered_rows,
            )
            record_count = 0
            writer = pq.ParquetWriter(
                tmp_path,
                schema,
                compression=compression,
                compression_level=compression_level,
                version="2.6",
                data_page_version="1.0",
                use_dictionary=True,
                write_statistics=True,
                use_compliant_nested_type=True,
            )
            try:
                combined = chain(sample_rows, iterator)
                while True:
                    batch_rows = list(islice(combined, row_group_rows))
                    if not batch_rows:
                        break
                    writer.write_table(pa.Table.from_pylist(batch_rows, schema=schema))
                    record_count += len(batch_rows)
                if record_count == 0:
                    writer.write_table(pa.Table.from_pylist([], schema=schema))
            finally:
                writer.close()
        with tmp_path.open("r+b") as handle:
            os.fsync(handle.fileno())
        atomic_replace(tmp_path, output)
    except Exception as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        finally:
            raise ParquetWriteError(f"{table_name}: failed to write {output}: {exc}") from exc
    return _inspect_parquet(
        pq=pq,
        path=output,
        table=table,
        record_count=record_count,
        row_group_target_bytes=row_group_target_bytes,
        spill_count=prepared.spill_count,
        maximum_rows_in_memory=max(prepared.peak_sort_buffer_rows, row_group_rows),
    )


def write_parquet_dataset(
    tables: Mapping[str, Iterable[Mapping[str, Any]]],
    output_dir: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
    compression: str = "ZSTD",
    compression_level: int = 9,
    canonical_sort: bool = True,
    row_group_target_bytes: int | None = None,
    maximum_buffered_rows: int = DEFAULT_MAXIMUM_BUFFERED_ROWS,
) -> Mapping[str, Path]:
    """Write multiple contract-bound tables under ``output_dir``."""

    schema_contract = contract if contract is not None else load_contract()
    root = Path(output_dir)
    written: dict[str, Path] = {}
    for table_name in sorted(tables):
        table = schema_contract.table(table_name)
        written[table_name] = write_parquet_table(
            table_name,
            tables[table_name],
            root / table.parquet_file,
            contract=schema_contract,
            compression=compression,
            compression_level=compression_level,
            canonical_sort=canonical_sort,
            row_group_target_bytes=row_group_target_bytes,
            maximum_buffered_rows=maximum_buffered_rows,
        )
    return dict(sorted(written.items()))

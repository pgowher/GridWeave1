"""Deterministic, metadata-only failure injection for VERCLO experiments."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum

from evidence.models import BackendValidation, CustodianReceipt
from verclo.models import ErasureCase


class FaultKind(StrEnum):
    OMIT_RECEIPT = "OMIT_RECEIPT"
    LATE_RECEIPT = "LATE_RECEIPT"
    CORRUPT_AUTHENTICATOR = "CORRUPT_AUTHENTICATOR"
    CORRUPT_ANCHOR = "CORRUPT_ANCHOR"
    DROP_MECHANISM_ATTESTATION = "DROP_MECHANISM_ATTESTATION"
    EQUIVOCATE_DISPOSITION = "EQUIVOCATE_DISPOSITION"
    COLLAPSE_CORROBORATOR_DOMAINS = "COLLAPSE_CORROBORATOR_DOMAINS"
    LOSE_AUTHENTICATED_BASELINE = "LOSE_AUTHENTICATED_BASELINE"


@dataclass(frozen=True)
class FaultSpec:
    kind: FaultKind
    target_receipt_ids: tuple[str, ...] = ()
    delay_seconds: int = 1
    conflicting_disposition: str = "FAILED"
    trust_domain: str = "TD-COLLUDING"
    fault_domain: str = "FD-COLLUDING"


@dataclass(frozen=True)
class FaultInjectionResult:
    case: ErasureCase
    receipts: tuple[CustodianReceipt, ...]
    validations: Mapping[str, BackendValidation]
    applied_faults: tuple[FaultKind, ...]
    mutation_log: tuple[str, ...]


class FaultInjector:
    """Applies an ordered fault plan without mutating caller-owned objects.

    Faults operate only on observer-visible metadata and explicit backend
    validation facts. Targets must resolve exactly; a miss is an experiment
    configuration error instead of a silent no-op.
    """

    def inject(
        self,
        case: ErasureCase,
        receipts: tuple[CustodianReceipt, ...],
        validations: Mapping[str, BackendValidation],
        faults: tuple[FaultSpec, ...],
    ) -> FaultInjectionResult:
        current_case = case
        current_receipts = {row.receipt_id: row for row in receipts}
        if len(current_receipts) != len(receipts):
            raise ValueError("receipt identifiers must be unique")
        current_validations = dict(validations)
        log: list[str] = []
        obligations = (
            {}
            if case.graph is None
            else {row.obligation_id: row for row in case.graph.obligations}
        )

        for fault in faults:
            targets = fault.target_receipt_ids
            if fault.kind == FaultKind.LOSE_AUTHENTICATED_BASELINE:
                if targets:
                    raise ValueError("baseline loss does not accept receipt targets")
                if current_case.graph is None:
                    raise ValueError(
                        "cannot invalidate an unavailable obligation graph"
                    )
                reasons = tuple(
                    sorted(
                        set(current_case.graph.baseline_reason_codes)
                        | {"INJECTED_BASELINE_LOSS"}
                    )
                )
                current_case = replace(
                    current_case,
                    graph=replace(
                        current_case.graph,
                        baseline_verifiable=False,
                        baseline_reason_codes=reasons,
                    ),
                )
                log.append("baseline:verifiable->false")
                continue

            if not targets:
                raise ValueError(f"{fault.kind} requires at least one target receipt")
            if len(targets) != len(set(targets)):
                raise ValueError(
                    f"{fault.kind} target receipt identifiers must be unique"
                )
            missing = tuple(sorted(set(targets) - set(current_receipts)))
            if missing:
                raise ValueError(f"fault targets do not exist: {missing}")

            if fault.kind == FaultKind.OMIT_RECEIPT:
                for receipt_id in targets:
                    del current_receipts[receipt_id]
                    current_validations.pop(receipt_id, None)
                    log.append(f"receipt:{receipt_id}:omitted")
                continue

            if fault.kind == FaultKind.LATE_RECEIPT:
                if fault.delay_seconds < 1:
                    raise ValueError("delay_seconds must be positive")
                for receipt_id in targets:
                    receipt = current_receipts[receipt_id]
                    obligation = obligations.get(receipt.obligation_id)
                    if obligation is None:
                        raise ValueError(
                            f"obligation unavailable for receipt: {receipt_id}"
                        )
                    late_at = obligation.deadline + timedelta(
                        seconds=fault.delay_seconds
                    )
                    current_receipts[receipt_id] = replace(
                        receipt, event_time=late_at, submitted_at=late_at
                    )
                    log.append(f"receipt:{receipt_id}:late-by-{fault.delay_seconds}s")
                continue

            if fault.kind in {
                FaultKind.CORRUPT_AUTHENTICATOR,
                FaultKind.CORRUPT_ANCHOR,
                FaultKind.DROP_MECHANISM_ATTESTATION,
            }:
                for receipt_id in targets:
                    validation = current_validations.get(receipt_id)
                    if validation is None:
                        raise ValueError(
                            f"validation unavailable for receipt: {receipt_id}"
                        )
                    if fault.kind == FaultKind.CORRUPT_AUTHENTICATOR:
                        validation = replace(validation, authenticator_valid=False)
                        suffix = "authenticator-corrupted"
                    elif fault.kind == FaultKind.CORRUPT_ANCHOR:
                        validation = replace(validation, anchor_valid=False)
                        suffix = "anchor-corrupted"
                    else:
                        validation = replace(
                            validation,
                            mechanism_present=False,
                            mechanism_valid=False,
                            mechanism_expires_at=None,
                        )
                        suffix = "mechanism-attestation-dropped"
                    current_validations[receipt_id] = validation
                    log.append(f"validation:{receipt_id}:{suffix}")
                continue

            if fault.kind == FaultKind.COLLAPSE_CORROBORATOR_DOMAINS:
                for receipt_id in targets:
                    current_receipts[receipt_id] = replace(
                        current_receipts[receipt_id],
                        trust_domain=fault.trust_domain,
                        fault_domain=fault.fault_domain,
                    )
                    log.append(f"receipt:{receipt_id}:domain-collapsed")
                continue

            if fault.kind == FaultKind.EQUIVOCATE_DISPOSITION:
                for receipt_id in targets:
                    original = current_receipts[receipt_id]
                    clone_id = f"{receipt_id}::EQUIVOCATED"
                    if clone_id in current_receipts:
                        raise ValueError(
                            f"equivocation identifier collision: {clone_id}"
                        )
                    current_receipts[clone_id] = replace(
                        original,
                        receipt_id=clone_id,
                        disposition=fault.conflicting_disposition,
                    )
                    if receipt_id in current_validations:
                        current_validations[clone_id] = current_validations[receipt_id]
                    log.append(f"receipt:{receipt_id}:equivocated-as:{clone_id}")
                continue

            raise ValueError(f"unsupported fault kind: {fault.kind}")

        return FaultInjectionResult(
            case=current_case,
            receipts=tuple(
                current_receipts[row_id] for row_id in sorted(current_receipts)
            ),
            validations=dict(sorted(current_validations.items())),
            applied_faults=tuple(row.kind for row in faults),
            mutation_log=tuple(log),
        )

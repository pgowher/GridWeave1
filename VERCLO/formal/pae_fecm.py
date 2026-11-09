"""Executable core of observer-relative federated erasure closure.

This module is a deliberately small, dependency-free mechanisation of
PAE-FM-2.2, Equations (11)--(32).  It is not VERCLO production code and it
does not consume evaluator-only truth.  The only input to ``evaluate`` is an
``ObserverView``.

Times are represented by integers.  Any injective, order-preserving encoding
of the normative UTC instants is therefore semantics preserving.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum, IntEnum


class Visibility(str, Enum):
    DECLARED = "DECLARED"
    DISCOVERABLE = "DISCOVERABLE"
    HIDDEN = "HIDDEN"


class Disposition(str, Enum):
    ERASED = "ERASED"
    CRYPTO_ERASED = "CRYPTO_ERASED"
    APPROVED_TRANSFORM = "APPROVED_TRANSFORM"
    FAILED = "FAILED"
    REFUSED = "REFUSED"
    UNREACHABLE = "UNREACHABLE"


class Grade(IntEnum):
    E0 = 0
    E1 = 1
    E2 = 2
    E3 = 3
    E4 = 4
    E5 = 5


class Outcome(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"
    CLOSED_WITH_EXCEPTIONS = "CLOSED_WITH_EXCEPTIONS"
    PARTIALLY_CLOSED = "PARTIALLY_CLOSED"
    OPEN = "OPEN"
    DISPUTED = "DISPUTED"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True, order=True)
class Asset:
    asset_id: str
    kind: str


@dataclass(frozen=True, order=True)
class Lineage:
    source: str
    target: str
    visibility: Visibility = Visibility.DECLARED
    authenticated: bool = True
    disclosed_at: int | None = None


@dataclass(frozen=True, order=True)
class Replica:
    replica_id: str
    asset_id: str
    repository_id: str
    custodian_id: str
    replica_class: str
    visibility: Visibility = Visibility.DECLARED
    authenticated: bool = True
    disclosed_at: int | None = None
    deadline: int | None = None
    minimum_grade: Grade | None = None
    allowed_dispositions: frozenset[Disposition] | None = None


@dataclass(frozen=True)
class Policy:
    applicable_asset_kinds: frozenset[str]
    applicable_replica_classes: frozenset[str]
    allowed_dispositions: frozenset[Disposition]
    minimum_grade: Grade
    exception_authorities: frozenset[str] = frozenset()
    early_closure_allowed: bool = False


@dataclass(frozen=True)
class Baseline:
    authorization_valid: bool = True
    policy_authenticated: bool = True
    scope_commitment_valid: bool = True
    obligation_commitment_valid: bool = True
    graph_available: bool = True
    committed_obligation_ids: frozenset[str] | None = None
    no_applicable_determination_valid: bool = False


@dataclass(frozen=True, order=True)
class Evidence:
    evidence_id: str
    obligation_id: str
    issuer_id: str
    disposition: Disposition
    event_time: int
    grade: Grade
    authenticated: bool = True
    binding_valid: bool = True
    integrity_valid: bool = True
    ordering_valid: bool = True
    chain_authenticated: bool = True
    sequence_contiguous: bool = True
    predecessors_available: bool = True


@dataclass(frozen=True, order=True)
class ExceptionClaim:
    exception_id: str
    obligation_ids: frozenset[str]
    authority_id: str
    basis_commitment: str
    effective_at: int
    expires_at: int
    authenticated: bool = True


@dataclass(frozen=True, order=True)
class Challenge:
    challenge_id: str
    authenticated: bool
    resolved: bool


@dataclass(frozen=True, order=True)
class Obligation:
    obligation_id: str
    asset_id: str
    replica_id: str
    repository_id: str
    custodian_id: str
    deadline: int
    minimum_grade: Grade
    allowed_dispositions: frozenset[Disposition]


@dataclass(frozen=True)
class ObserverView:
    evaluation_time: int
    case_deadline: int
    root_asset_ids: frozenset[str]
    policy: Policy
    baseline: Baseline
    assets: tuple[Asset, ...]
    lineage: tuple[Lineage, ...]
    replicas: tuple[Replica, ...]
    evidence: tuple[Evidence, ...] = ()
    exceptions: tuple[ExceptionClaim, ...] = ()
    challenges: tuple[Challenge, ...] = ()


@dataclass(frozen=True)
class Evaluation:
    outcome: Outcome
    discovered_assets: frozenset[str]
    obligations: tuple[Obligation, ...]
    successful: frozenset[str]
    excepted: frozenset[str]
    resolved: frozenset[str]
    conflict_obligations: frozenset[str]
    baseline_verifiable: bool
    contradiction_free: bool
    ready: bool


def visible(
    visibility: Visibility,
    authenticated: bool,
    disclosed_at: int | None,
    at: int,
) -> bool:
    """Equation (11): membership in the observer-visible snapshot."""

    return visibility is Visibility.DECLARED or (
        visibility is Visibility.DISCOVERABLE
        and authenticated
        and disclosed_at is not None
        and disclosed_at <= at
    )


def dependency_closure(
    roots: Iterable[str], lineage: Iterable[Lineage], at: int
) -> frozenset[str]:
    """Least fixed point from Equations (12)--(13)."""

    reached = set(roots)
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in lineage:
        if (
            visible(edge.visibility, edge.authenticated, edge.disclosed_at, at)
            and edge.authenticated
        ):
            adjacency[edge.source].add(edge.target)
    queue = deque(sorted(reached))
    while queue:
        source = queue.popleft()
        for target in sorted(adjacency[source]):
            if target not in reached:
                reached.add(target)
                queue.append(target)
    return frozenset(reached)


def _acyclic(vertices: set[str], edges: Iterable[Lineage]) -> bool:
    indegree = {vertex: 0 for vertex in vertices}
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge.source not in vertices or edge.target not in vertices:
            return False
        if edge.target not in adjacency[edge.source]:
            adjacency[edge.source].add(edge.target)
            indegree[edge.target] += 1
    queue = deque(sorted(v for v, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        source = queue.popleft()
        visited += 1
        for target in sorted(adjacency[source]):
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited == len(vertices)


def induce_obligations(
    view: ObserverView, discovered: frozenset[str]
) -> tuple[Obligation, ...]:
    """Policy transformation from Equations (14)--(16)."""

    assets = {asset.asset_id: asset for asset in view.assets}
    obligations: list[Obligation] = []
    for replica in view.replicas:
        if not visible(
            replica.visibility,
            replica.authenticated,
            replica.disclosed_at,
            view.evaluation_time,
        ):
            continue
        asset = assets.get(replica.asset_id)
        if asset is None or asset.asset_id not in discovered:
            continue
        if asset.kind not in view.policy.applicable_asset_kinds:
            continue
        if replica.replica_class not in view.policy.applicable_replica_classes:
            continue
        obligations.append(
            Obligation(
                obligation_id=f"OBL::{asset.asset_id}::{replica.replica_id}",
                asset_id=asset.asset_id,
                replica_id=replica.replica_id,
                repository_id=replica.repository_id,
                custodian_id=replica.custodian_id,
                deadline=(
                    replica.deadline
                    if replica.deadline is not None
                    else view.case_deadline
                ),
                minimum_grade=(
                    replica.minimum_grade
                    if replica.minimum_grade is not None
                    else view.policy.minimum_grade
                ),
                allowed_dispositions=(
                    replica.allowed_dispositions
                    if replica.allowed_dispositions is not None
                    else view.policy.allowed_dispositions
                ),
            )
        )
    return tuple(sorted(obligations))


def _scope_complete(view: ObserverView) -> bool:
    assets = {asset.asset_id: asset for asset in view.assets}
    visible_edges = tuple(
        edge
        for edge in view.lineage
        if visible(
            edge.visibility, edge.authenticated, edge.disclosed_at, view.evaluation_time
        )
    )
    visible_replicas = tuple(
        replica
        for replica in view.replicas
        if visible(
            replica.visibility,
            replica.authenticated,
            replica.disclosed_at,
            view.evaluation_time,
        )
    )
    unique_assets = len(assets) == len(view.assets)
    unique_replicas = len({row.replica_id for row in visible_replicas}) == len(
        visible_replicas
    )
    endpoints_resolve = all(
        edge.source in assets and edge.target in assets for edge in visible_edges
    ) and all(replica.asset_id in assets for replica in visible_replicas)
    authenticated = all(edge.authenticated for edge in visible_edges) and all(
        replica.authenticated for replica in visible_replicas
    )
    return all(
        (
            view.baseline.scope_commitment_valid,
            view.baseline.graph_available,
            view.root_asset_ids <= assets.keys(),
            unique_assets,
            unique_replicas,
            endpoints_resolve,
            authenticated,
            _acyclic(set(assets), visible_edges),
        )
    )


def _admissible(evidence: Evidence, obligation: Obligation, at: int) -> bool:
    """Evidence admissibility from Equations (21)--(22)."""

    return all(
        (
            evidence.obligation_id == obligation.obligation_id,
            evidence.issuer_id == obligation.custodian_id,
            evidence.event_time <= at,
            evidence.authenticated,
            evidence.binding_valid,
            evidence.integrity_valid,
            evidence.ordering_valid,
            evidence.grade >= obligation.minimum_grade,
            evidence.chain_authenticated,
            evidence.sequence_contiguous,
            evidence.predecessors_available,
        )
    )


def _valid_exception(
    claim: ExceptionClaim, obligation: Obligation, policy: Policy, at: int
) -> bool:
    """Policy-relative exception validity from Equation (26)."""

    return all(
        (
            obligation.obligation_id in claim.obligation_ids,
            claim.authenticated,
            claim.authority_id in policy.exception_authorities,
            bool(claim.basis_commitment),
            claim.effective_at <= obligation.deadline,
            claim.effective_at <= at,
            at < claim.expires_at,
        )
    )


def decide_abstract(
    *,
    ready: bool,
    baseline_verifiable: bool,
    conflict_or_challenge: bool,
    obligation_ids: frozenset[str],
    successful: frozenset[str],
    excepted: frozenset[str],
) -> Outcome:
    """The precedence rule in Equation (32), isolated for model checking."""

    # Callers may carry rejected records for diagnostics. Only resolutions of
    # induced obligations participate in Equation (32).
    successful = successful & obligation_ids
    excepted = excepted & obligation_ids
    if not ready:
        return Outcome.IN_PROGRESS
    if not baseline_verifiable:
        return Outcome.UNVERIFIABLE
    if conflict_or_challenge:
        return Outcome.DISPUTED
    resolved = successful | excepted
    if obligation_ids <= successful:
        return Outcome.CLOSED
    if obligation_ids <= resolved and bool(excepted):
        return Outcome.CLOSED_WITH_EXCEPTIONS
    if resolved:
        return Outcome.PARTIALLY_CLOSED
    return Outcome.OPEN


def evaluate(view: ObserverView) -> Evaluation:
    """Evaluate only the authenticated observer view; hidden truth is absent."""

    discovered = dependency_closure(
        view.root_asset_ids, view.lineage, view.evaluation_time
    )
    obligations = induce_obligations(view, discovered)
    by_id: Mapping[str, Obligation] = {row.obligation_id: row for row in obligations}
    obligation_ids = frozenset(by_id)

    commitment_matches = (
        view.baseline.committed_obligation_ids is None
        or view.baseline.committed_obligation_ids == obligation_ids
    )
    baseline_verifiable = all(
        (
            view.baseline.authorization_valid,
            view.baseline.policy_authenticated,
            _scope_complete(view),
            view.baseline.obligation_commitment_valid,
            commitment_matches,
            bool(obligations) or view.baseline.no_applicable_determination_valid,
        )
    )

    admissible: dict[str, list[Evidence]] = defaultdict(list)
    successful: set[str] = set()
    for evidence in view.evidence:
        obligation = by_id.get(evidence.obligation_id)
        if obligation is None or not _admissible(
            evidence, obligation, view.evaluation_time
        ):
            continue
        admissible[obligation.obligation_id].append(evidence)
        if (
            evidence.disposition in obligation.allowed_dispositions
            and evidence.event_time <= obligation.deadline
        ):
            successful.add(obligation.obligation_id)

    excepted = {
        obligation.obligation_id
        for obligation in obligations
        for claim in view.exceptions
        if _valid_exception(claim, obligation, view.policy, view.evaluation_time)
    }
    conflicts = {
        obligation_id
        for obligation_id, rows in admissible.items()
        if len({row.disposition for row in rows}) > 1
    }
    active_challenge = any(
        challenge.authenticated and not challenge.resolved
        for challenge in view.challenges
    )
    terminal_reports = frozenset(admissible) | frozenset(excepted)
    ready = view.evaluation_time >= view.case_deadline or (
        view.policy.early_closure_allowed
        and (bool(obligations) or view.baseline.no_applicable_determination_valid)
        and obligation_ids <= terminal_reports
    )
    outcome = decide_abstract(
        ready=ready,
        baseline_verifiable=baseline_verifiable,
        conflict_or_challenge=bool(conflicts) or active_challenge,
        obligation_ids=obligation_ids,
        successful=frozenset(successful),
        excepted=frozenset(excepted),
    )
    return Evaluation(
        outcome=outcome,
        discovered_assets=discovered,
        obligations=obligations,
        successful=frozenset(successful),
        excepted=frozenset(excepted),
        resolved=frozenset(successful | excepted),
        conflict_obligations=frozenset(conflicts),
        baseline_verifiable=baseline_verifiable,
        contradiction_free=not conflicts and not active_challenge,
        ready=ready,
    )

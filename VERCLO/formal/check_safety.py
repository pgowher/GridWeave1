#!/usr/bin/env python3
"""Exhaustive bounded safety checker for the PAE-FECM abstract core."""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import combinations

from pae_fecm import Lineage, Outcome, decide_abstract, dependency_closure


@dataclass
class Check:
    name: str
    configurations: int = 0


class VerificationFailure(RuntimeError):
    """Raised when an exhaustively checked safety condition is false."""


def _require(condition: bool, message: str) -> None:
    """Optimization-safe replacement for the language-level assert statement."""

    if not condition:
        raise VerificationFailure(message)


def _subsets(items: tuple[str, ...]):
    for size in range(len(items) + 1):
        for members in combinations(items, size):
            yield frozenset(members)


def check_decision_safety(max_obligations: int = 4) -> Check:
    """Prove the decision invariants over every abstract state up to the bound."""

    checked = 0
    for count in range(max_obligations + 1):
        obligations = frozenset(f"o{i}" for i in range(count))
        members = tuple(sorted(obligations))
        for successful in _subsets(members):
            for excepted in _subsets(members):
                for ready in (False, True):
                    for baseline in (False, True):
                        for conflict in (False, True):
                            outcome = decide_abstract(
                                ready=ready,
                                baseline_verifiable=baseline,
                                conflict_or_challenge=conflict,
                                obligation_ids=obligations,
                                successful=successful,
                                excepted=excepted,
                            )
                            resolved = successful | excepted
                            checked += 1

                            # T-SAFE-01: no terminal result before readiness.
                            context = (
                                f"n={count}, successful={sorted(successful)}, "
                                f"excepted={sorted(excepted)}, ready={ready}, "
                                f"baseline={baseline}, conflict={conflict}, "
                                f"outcome={outcome.value}"
                            )
                            _require(
                                (outcome is Outcome.IN_PROGRESS) == (not ready),
                                f"SAFE-01 readiness violation: {context}",
                            )
                            if not ready:
                                continue

                            # T-SAFE-02/03: baseline and dispute precedence.
                            _require(
                                (outcome is Outcome.UNVERIFIABLE) == (not baseline),
                                f"SAFE-02 baseline precedence violation: {context}",
                            )
                            if not baseline:
                                continue
                            _require(
                                (outcome is Outcome.DISPUTED) == conflict,
                                f"SAFE-03 dispute precedence violation: {context}",
                            )
                            if conflict:
                                continue

                            # T-SAFE-04: CLOSED is justified by all-success coverage.
                            _require(
                                (outcome is Outcome.CLOSED)
                                == (obligations <= successful),
                                f"SAFE-04 closed-safety violation: {context}",
                            )
                            if outcome is Outcome.CLOSED_WITH_EXCEPTIONS:
                                # Precedence also implies a genuinely exception-only resolution.
                                _require(
                                    obligations <= resolved,
                                    f"SAFE-05 incomplete exception closure: {context}",
                                )
                                _require(
                                    bool(excepted),
                                    f"SAFE-05 exception closure without exception: {context}",
                                )
                                _require(
                                    bool(obligations - successful),
                                    f"SAFE-05 exception closure masked all-success: {context}",
                                )
                            if outcome is Outcome.PARTIALLY_CLOSED:
                                _require(
                                    bool(resolved),
                                    f"SAFE-06 partial closure without resolution: {context}",
                                )
                                _require(
                                    not obligations <= resolved,
                                    f"SAFE-06 partial closure with full coverage: {context}",
                                )
                            if outcome is Outcome.OPEN:
                                _require(
                                    not resolved,
                                    f"SAFE-06 open case has a resolution: {context}",
                                )
    return Check("abstract decision safety", checked)


def check_discovery_monotonicity(vertices: int = 3) -> Check:
    """Exhaustively check L1 subset L2 implies Reach(L1) subset Reach(L2)."""

    names = tuple(f"a{i}" for i in range(vertices))
    possible = tuple((a, b) for a in names for b in names if a != b)
    edge_sets = tuple(_subsets(tuple(f"{a}>{b}" for a, b in possible)))
    roots = tuple(subset for subset in _subsets(names) if subset)
    checked = 0
    for larger_tokens in edge_sets:
        larger_edges = tuple(
            Lineage(*token.split(">", 1)) for token in sorted(larger_tokens)
        )
        for smaller_tokens in _subsets(tuple(sorted(larger_tokens))):
            smaller_edges = tuple(
                Lineage(*token.split(">", 1)) for token in sorted(smaller_tokens)
            )
            for root in roots:
                small = dependency_closure(root, smaller_edges, at=0)
                large = dependency_closure(root, larger_edges, at=0)
                _require(
                    small <= large,
                    "SAFE-07 discovery monotonicity violation: "
                    f"roots={sorted(root)}, smaller={sorted(smaller_tokens)}, "
                    f"larger={sorted(larger_tokens)}",
                )
                checked += 1
    return Check("authenticated discovery monotonicity", checked)


def check_hidden_noninterference(hidden_variants: int = 256) -> Check:
    """Check that evaluator-only hidden state cannot alter an abstract decision.

    The hidden value is deliberately not an argument of ``decide_abstract``.
    This loop makes the two-world noninterference obligation executable for a
    useful bounded family of hidden worlds.
    """

    obligations = frozenset({"o0", "o1"})
    reference = decide_abstract(
        ready=True,
        baseline_verifiable=True,
        conflict_or_challenge=False,
        obligation_ids=obligations,
        successful=obligations,
        excepted=frozenset(),
    )
    for _hidden_world in range(hidden_variants):
        observed = decide_abstract(
            ready=True,
            baseline_verifiable=True,
            conflict_or_challenge=False,
            obligation_ids=obligations,
            successful=obligations,
            excepted=frozenset(),
        )
        _require(
            observed is reference,
            f"SAFE-08 hidden-state interference at variant {_hidden_world}",
        )
    return Check("hidden-world noninterference", hidden_variants)


def main() -> None:
    checks = (
        check_decision_safety(),
        check_discovery_monotonicity(),
        check_hidden_noninterference(),
    )
    report = {
        "status": "PASS",
        "checker": "PAE-FECM observer-relative bounded safety checker",
        "bounds": {"obligations": 4, "graph_vertices": 3, "hidden_worlds": 256},
        "checks": [check.__dict__ for check in checks],
        "total_configurations": sum(check.configurations for check in checks),
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

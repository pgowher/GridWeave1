"""Pair-closed diagnostic coverage selection.

The atomic candidates are complete control/challenge witnesses, never individual
rows. The bitset DP is conventional weighted set cover over a bounded universe;
the domain-specific object and workflow, not set cover itself, are candidates
for a research contribution. Exact optimality applies only to the supplied
candidate pool, additive serialized-byte cost and requested diagnostic tags.
"""
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256


@dataclass(frozen=True)
class Candidate:
    pair_id: str
    tags: frozenset[str]
    cost: int


class StateLimitExceeded(ValueError):
    pass


def select(candidates, goals=None, *, strategy="auto", max_states=100_000, seed="baseline"):
    candidates=tuple(sorted(candidates,key=lambda x:x.pair_id))
    if not candidates or len({c.pair_id for c in candidates})!=len(candidates):
        raise ValueError("nonempty candidates with unique pair IDs required")
    if any(type(c.cost) is not int or c.cost<=0 for c in candidates):
        raise ValueError("cost must be a positive integer")
    universe=frozenset().union(*(c.tags for c in candidates))
    goals=frozenset(universe if goals is None else goals)
    if not goals<=universe:raise ValueError("unreachable diagnostic coverage goals")
    if strategy not in {"auto","exact","greedy","all","random"}:raise ValueError("unknown strategy")
    if max_states<1:raise ValueError("max_states must be positive")
    states_seen=0;pruned=0;fallback=False
    if strategy=="all":chosen=candidates;solver="ALL"
    elif strategy=="random":
        chosen=[];covered=set()
        for c in sorted(candidates,key=lambda c:sha256((seed+c.pair_id).encode()).digest()):
            if goals<=covered:break
            chosen.append(c);covered.update(c.tags)
        solver="SEEDED_RANDOM_UNTIL_COVERED"
    elif strategy=="greedy":chosen=_greedy(candidates,goals);solver="GREEDY"
    else:
        # Safe dominance pruning for additive independent pair costs. At least
        # one strict relation avoids removing both identical candidates.
        useful=[]
        for c in candidates:
            if any((c.tags&goals)<=(d.tags&goals) and
                   (d.cost<c.cost or (d.cost==c.cost and d.pair_id<c.pair_id))
                   for d in candidates):pruned+=1
            else:useful.append(c)
        bits={tag:1<<i for i,tag in enumerate(sorted(goals))}
        target=(1<<len(bits))-1
        dp={0:(0,())}
        try:
            for c in useful:
                cm=sum(bits[t] for t in c.tags&goals)
                for mask,(cost,witness) in tuple(dp.items()):
                    dest=mask|cm;value=(cost+c.cost,tuple(sorted((*witness,c.pair_id))))
                    if dest!=mask and (dest not in dp or value<dp[dest]):dp[dest]=value
                states_seen=max(states_seen,len(dp))
                if len(dp)>max_states:raise StateLimitExceeded(f"exact coverage DP exceeded {max_states} states")
            ids=set(dp[target][1]);chosen=[c for c in candidates if c.pair_id in ids];solver="EXACT_BITSET_DP"
        except StateLimitExceeded:
            if strategy=="exact":raise
            fallback=True;chosen=_greedy(candidates,goals);solver="GREEDY_STATE_LIMIT_FALLBACK"
    covered=frozenset().union(*(c.tags for c in chosen))
    assert goals<=covered
    return {"selected_pair_ids":sorted(c.pair_id for c in chosen),
            "cost_bytes":sum(c.cost for c in chosen),"candidate_cost_bytes":sum(c.cost for c in candidates),
            "requested_goals":sorted(goals),"covered_goals":sorted(goals&covered),
            "solver":solver,"optimal_for_declared_problem":solver=="EXACT_BITSET_DP",
            "state_limit_fallback":fallback,"states_seen":states_seen,"dominated_candidates":pruned,
            "candidate_pairs":len(candidates),"selected_pairs":len(chosen)}


def _greedy(candidates,goals):
    chosen=[];covered=set()
    remaining=list(candidates)
    while not goals<=covered:
        available=[c for c in remaining if (c.tags&goals)-covered]
        c=min(available,key=lambda c:(-Fraction(len((c.tags&goals)-covered),c.cost),c.cost,c.pair_id))
        chosen.append(c);covered.update(c.tags);remaining.remove(c)
    return chosen

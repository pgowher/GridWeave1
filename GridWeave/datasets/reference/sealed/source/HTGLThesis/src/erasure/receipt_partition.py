"""Ordered receipt partitioning; a conventional hash-index baseline."""
from collections import defaultdict
from types import MappingProxyType


class ReceiptPartition:
    def __init__(self, groups):
        self._groups = MappingProxyType({key: tuple(rows) for key, rows in groups.items()})

    @classmethod
    def from_rows(cls, rows):
        groups = defaultdict(list)
        for row in rows:
            groups[row.obligation_id].append(row)
        return cls(groups)

    def matching(self, obligation_id, rejected=()):
        rows = self._groups.get(obligation_id, ())
        return tuple(row for row in rows if row.receipt_id not in rejected) if rejected else rows

    def __iter__(self):
        for rows in self._groups.values():
            yield from rows

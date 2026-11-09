from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from htgl_dataset_generator import _atomic  # noqa: E402


class AtomicReplaceTests(unittest.TestCase):
    @staticmethod
    def _permission_error(winerror: int) -> PermissionError:
        error = PermissionError(13, "access denied")
        error.winerror = winerror
        return error

    def test_transient_windows_access_denial_is_retried_with_bounded_wait(self) -> None:
        transient = self._permission_error(5)
        with (
            patch.object(_atomic.os, "name", "nt"),
            patch.object(_atomic.os, "replace", side_effect=(transient, None)) as replace,
            patch.object(_atomic._WAIT_EVENT, "wait", return_value=False) as wait,
        ):
            _atomic.atomic_replace("source", "target")
        self.assertEqual(2, replace.call_count)
        wait.assert_called_once_with(_atomic._RETRY_DELAYS_SECONDS[0])

    def test_non_sharing_permission_error_is_not_hidden(self) -> None:
        permanent = self._permission_error(87)
        with (
            patch.object(_atomic.os, "name", "nt"),
            patch.object(_atomic.os, "replace", side_effect=permanent) as replace,
            patch.object(_atomic._WAIT_EVENT, "wait", return_value=False) as wait,
        ):
            with self.assertRaises(PermissionError):
                _atomic.atomic_replace("source", "target")
        replace.assert_called_once()
        wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()

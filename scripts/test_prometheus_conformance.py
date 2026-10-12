"""Exercise transient query failures and diagnostics without real sleeps or servers."""

import io
import json
import pathlib
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

import prometheus_conformance as oracle


class QueryTests(unittest.TestCase):
    def test_transient_network_errors_retry_until_success(self):
        for error in (
            urllib.error.URLError("not ready"),
            ConnectionRefusedError("refused"),
            TimeoutError("timed out"),
        ):
            with self.subTest(error=error):
                response = Mock()
                response.__enter__ = Mock(
                    return_value=io.StringIO(
                        json.dumps({"status": "success", "data": {"result": [42]}})
                    )
                )
                response.__exit__ = Mock(return_value=False)
                with (
                    patch.object(oracle.time, "monotonic", side_effect=[0, 0, 0.25]),
                    patch.object(oracle.time, "sleep") as sleep,
                    patch.object(
                        oracle.urllib.request, "urlopen", side_effect=[error, response]
                    ) as request,
                ):
                    self.assertEqual(oracle.query(1234, "app_x", 1), [42])
                self.assertEqual(request.call_count, 2)
                self.assertEqual(request.call_args.kwargs["timeout"], 0.75)
                sleep.assert_called_once_with(0.25)

    def test_deadline_names_query_and_last_error(self):
        with (
            patch.object(oracle.time, "monotonic", side_effect=[0, 1]),
            patch.object(oracle.time, "sleep") as sleep,
            patch.object(
                oracle.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError("connection refused"),
            ),
            self.assertRaisesRegex(
                AssertionError, "app_x.*deadline.*connection refused"
            ),
        ):
            oracle.query(1234, "app_x", 1)
        sleep.assert_not_called()


class ServerLogTests(unittest.TestCase):
    def test_second_attempt_failure_reports_second_attempt_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            (directory / "prometheus-0.log").write_text("first bind race")
            active_log = directory / "prometheus-1.log"
            active_log.write_text("second attempt crashed")
            (directory / "collector.log").write_text("collector")
            prom = Mock()
            prom.poll.return_value = 1
            collector = Mock()
            collector.poll.return_value = None
            with (
                patch.object(oracle.tempfile, "TemporaryDirectory") as temporary_dir,
                patch.object(oracle.shutil, "which", return_value="binary"),
                patch.object(oracle.subprocess, "run"),
                patch.object(
                    oracle,
                    "run_case",
                    side_effect=lambda binary, directory, case, rows: (
                        case,
                        case,
                        "job",
                        {},
                    ),
                ),
                patch.object(
                    oracle,
                    "start_servers",
                    return_value=(1234, prom, collector, active_log),
                ),
                self.assertRaisesRegex(AssertionError, "second attempt crashed"),
            ):
                temporary_dir.return_value.__enter__.return_value = str(directory)
                oracle.main()


if __name__ == "__main__":
    unittest.main()

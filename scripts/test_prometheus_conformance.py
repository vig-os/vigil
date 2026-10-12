"""Exercise transient query failures and diagnostics without real sleeps or servers."""

import http.client
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
            ConnectionResetError("reset"),
            http.client.IncompleteRead(b"partial"),
            json.JSONDecodeError("invalid", "", 0),
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

    def test_expired_deadline_never_requests(self):
        with (
            patch.object(oracle.time, "monotonic", return_value=1),
            patch.object(oracle.urllib.request, "urlopen") as request,
            self.assertRaisesRegex(AssertionError, "app_x.*deadline"),
        ):
            oracle.query(1234, "app_x", 1)
        request.assert_not_called()

    def test_sleep_is_capped_by_remaining_deadline(self):
        with (
            patch.object(oracle.time, "monotonic", side_effect=[0, 0.9, 1]),
            patch.object(oracle.time, "sleep") as sleep,
            patch.object(
                oracle.urllib.request,
                "urlopen",
                side_effect=ConnectionResetError("reset"),
            ) as request,
            self.assertRaisesRegex(AssertionError, "app_x.*deadline.*reset"),
        ):
            oracle.query(1234, "app_x", 1)
        self.assertAlmostEqual(sleep.call_args.args[0], 0.1)
        self.assertEqual(request.call_count, 1)

    def test_client_http_errors_fail_immediately(self):
        for code in (400, 401, 404, 429):
            error = urllib.error.HTTPError("url", code, "bad query", {}, io.BytesIO())
            self.addCleanup(error.close)
            with (
                self.subTest(code=code),
                patch.object(oracle.time, "monotonic", side_effect=[0, 0, 1]),
                patch.object(oracle.time, "sleep") as sleep,
                patch.object(
                    oracle.urllib.request,
                    "urlopen",
                    side_effect=error,
                ) as request,
                self.assertRaisesRegex(AssertionError, "app_x.*bad query"),
            ):
                oracle.query(1234, "app_x", 1)
            request.assert_called_once()
            sleep.assert_not_called()

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
    def test_start_servers_selects_second_attempt_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            first, second, collector = Mock(), Mock(), Mock()
            first.poll.return_value = 1
            second.poll.return_value = None
            response = Mock()
            response.__enter__ = Mock(return_value=Mock(status=200))
            response.__exit__ = Mock(return_value=False)

            def spawn(command, **kwargs):
                if command[0] == "prometheus":
                    kwargs["stdout"].write("address already in use")
                    return first if "tsdb-0" in command[-1] else second
                return collector

            with (
                patch.object(oracle.subprocess, "Popen", side_effect=spawn) as popen,
                patch.object(oracle.urllib.request, "urlopen", return_value=response),
                patch.object(oracle, "free_port", side_effect=[1234, 5678]),
            ):
                children = []
                port, prom, col, log = oracle.start_servers(directory, children)
            self.assertEqual(
                (port, prom, col, log),
                (5678, second, collector, directory / "prometheus-1.log"),
            )
            self.assertEqual(children, [first, second, collector])
            self.assertIn("prometheus-1.json", popen.call_args_list[1].args[0][-2])
            self.assertIn("tsdb-1", popen.call_args_list[1].args[0][-1])

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

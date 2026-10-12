"""Compare vigil output by meaning using the pinned Collector as reference reader."""

import collections
import gzip
import json
import os
import pathlib
import subprocess
import tempfile
import time


def require(condition, message):
    """Checks remain active under python -O."""
    if not condition:
        raise AssertionError(message)


def normalize(value):
    """Preserve AnyValue tags; only protobuf message defaults may disappear."""
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in (
            "intValue",
            "timeUnixNano",
            "observedTimeUnixNano",
            "startTimeUnixNano",
            "count",
            "asInt",
        ):
            item = str(int(item))
        if key == "explicitBounds":
            item = [float(bound) for bound in item]
        if key == "bucketCounts":
            item = [str(int(count)) for count in item]
        if key in ("intValue", "timeUnixNano", "observedTimeUnixNano"):
            item = str(int(item))
        if key == "doubleValue" and isinstance(item, (int, float)):
            item = float(item) if item != 0 else 0.0
        if key in ("traceId", "spanId") and item:
            require(
                len(item) == {"traceId": 32, "spanId": 16}[key], f"Invalid {key} length"
            )
            require(
                all(char in "0123456789abcdefABCDEF" for char in item),
                f"Invalid {key} hex",
            )
            item = item.lower()
        # AnyValue scalar defaults retain their type and must never be erased.
        if (
            not key.endswith("Value") and (item in ("", [], {}, None) or item == 0)
        ) or (key in ("timeUnixNano", "observedTimeUnixNano") and item == "0"):
            continue
        item = normalize(item)
        if key in ("attributes", "values") and isinstance(item, list):
            if key == "attributes" or all(
                isinstance(v, dict) and "key" in v for v in item
            ):
                item = sorted(item, key=lambda v: json.dumps(v, sort_keys=True))
        result[key] = item
    return result


def records(messages):
    result = collections.Counter()
    for message in messages:
        for resource in message["resourceLogs"]:
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    identity = [
                        {k: v for k, v in resource.items() if k != "scopeLogs"},
                        {k: v for k, v in scope.items() if k != "logRecords"},
                        record,
                    ]
                    result[json.dumps(normalize(identity), sort_keys=True)] += 1
    return result


def metric_points(messages):
    """Compare repeated metric metadata and points independently of splits."""
    result = collections.Counter()
    for message in messages:
        for resource in message["resourceMetrics"]:
            for scope in resource.get("scopeMetrics", []):
                for metric in scope.get("metrics", []):
                    field = next(
                        k for k in ("sum", "gauge", "histogram") if k in metric
                    )
                    for point in metric[field]["dataPoints"]:
                        identity = [
                            {k: v for k, v in resource.items() if k != "scopeMetrics"},
                            {k: v for k, v in scope.items() if k != "metrics"},
                            {k: v for k, v in metric.items() if k != field},
                            {
                                k: v
                                for k, v in metric[field].items()
                                if k != "dataPoints"
                            },
                            point,
                        ]
                        result[json.dumps(normalize(identity), sort_keys=True)] += 1
    return result


def json_lines(text):
    """JSON Lines delimiters are LF, not Unicode NEL/line/paragraph separators."""
    return [line for line in text.split("\n") if line]


def raw_reader_cases():
    """Shared #82 fixtures: the real Collector must drop each raw escape."""
    fixtures = pathlib.Path(__file__).resolve().parents[1] / "tests/fixtures/audit"
    base = json.loads(json_lines((fixtures / "codec.jsonl").read_text())[0])
    for index, case in enumerate(
        json.loads((fixtures / "raw-fields.json").read_text())
    ):
        message = json.loads(json.dumps(base))
        resource = message["resourceLogs"][0]
        resource["resource"]["attributes"].append(
            {"key": "raw.parity.case", "value": {"stringValue": str(index)}}
        )
        if case["field"] == "bytesValue":
            resource["resource"]["attributes"].append(
                {"key": "raw.bytes", "value": {"bytesValue": "RAW"}}
            )
        else:
            resource["scopeLogs"][0]["logRecords"][0][case["field"]] = "RAW"
        yield json.dumps(message).replace('"RAW"', case["raw"]), case["accepted"]


def main():
    subprocess.run(["otelcol-contrib", "--version"], check=True)
    with tempfile.TemporaryDirectory(prefix="vigil-conformance-") as temporary:
        directory = pathlib.Path(temporary)
        subprocess.run(
            ["cargo", "run", "--locked", "--example", "conformance", "--", temporary],
            check=True,
            env=os.environ
            | {
                "VIGIL_DIR": str(directory / "bridge"),
                "RUST_LOG": "info",
                "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fvigil_unstable",
            },
        )
        # Compare a normal two-instrument run with the same run poisoning one
        # name before its first export. Only the poisoned file feeds the Collector.
        identity_files = []
        for mode in ("identity-baseline", "identity-poisoned"):
            destination = directory / mode
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--locked",
                    "--example",
                    "conformance",
                    "--",
                    str(destination),
                    mode,
                ],
                check=True,
                env=os.environ | {"CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fvigil_unstable"},
            )
            identity_files.append((destination / "metrics.jsonl").read_text())
        baseline, poisoned = identity_files
        require(len(poisoned) < len(baseline), "poisoning must shorten metrics output")
        require(
            "conformance.conflict" in baseline, "baseline conflict instrument missing"
        )
        require(
            "conformance.conflict" not in poisoned, "poisoned metric escaped the filter"
        )
        require("conformance.kept" in poisoned, "healthy metric was removed")
        with (directory / "metrics.jsonl").open("a") as stream:
            stream.write(poisoned)
        inputs = sorted(
            path
            for path in directory.glob("logs-*.jsonl")
            if not path.name.startswith("logs-unterminated-")
        )
        require(len(inputs) > 1, "rotation did not happen")
        # Empty lines and terminated garbage between valid neighbouring batches.
        lines = json_lines(inputs[0].read_text())
        require(lines, "first rotated file is empty")
        neighbour = inputs[1].read_text()
        inputs[0].write_text("\n" + "\n".join(lines) + "\n\ngarbage\n\n" + neighbour)
        inputs[1].write_text("")
        parity = list(raw_reader_cases())
        parity_path = directory / "logs-raw-fields.jsonl"
        parity_path.write_text("\n".join(line for line, _ in parity) + "\n")
        inputs.append(parity_path)
        manifest = json.loads((directory / "manifest.json").read_text())
        corpus = (
            pathlib.Path(__file__).resolve().parents[1]
            / "tests/fixtures/audit/roundtrip.jsonl.gz"
        )
        writer_lines = json_lines(gzip.decompress(corpus.read_bytes()).decode())
        require(
            len(writer_lines) == 256, "writer corpus must contain 256 generated lines"
        )
        writer_path = directory / "logs-writer-corpus.jsonl"
        writer_path.write_text("\n".join(writer_lines) + "\n")
        inputs.append(writer_path)
        expected = records(
            manifest
            + [json.loads(line) for line, ok in parity if ok]
            + [json.loads(line) for line in writer_lines]
        )
        require(expected, "manifest must contain records")
        for path in inputs:
            require(
                all(len(line) <= 1_000_000 for line in path.read_bytes().split(b"\n")),
                f"Oversized line in {path}",
            )
        manifest_records = [json.loads(key)[2] for key in expected]

        def attribute(record, key):
            return next(
                (a["value"] for a in record.get("attributes", []) if a["key"] == key),
                {},
            )

        require(
            sum(
                attribute(r, "case").get("stringValue") == "large-batch"
                for r in manifest_records
            )
            == 1024,
            "large batch fixture missing records",
        )
        oversized = [
            r
            for r in manifest_records
            if attribute(r, "case").get("stringValue") == "oversized"
        ]
        require(
            len(oversized) == 1
            and attribute(oversized[0], "vigil.truncated").get("boolValue") is True,
            "oversized tracing record must have truncation marker",
        )
        require(
            int(attribute(oversized[0], "vigil.original_size").get("intValue", 0))
            > 3 * 1024 * 1024,
            "original size must describe the oversized line",
        )
        dropped = [
            r
            for r in manifest_records
            if attribute(r, "vigil.dropped").get("boolValue") is True
        ]
        require(
            len(dropped) == 1,
            "unshrinkable record must produce exactly one dropped stub",
        )
        require(
            attribute(dropped[0], "vigil.truncated").get("boolValue") is True,
            "dropped stub must carry the truncation marker",
        )
        require(
            dropped[0]["body"]["stringValue"].startswith("vigil: record dropped:"),
            "dropped stub must explain its replacement",
        )
        resources = {json.dumps(json.loads(key)[0], sort_keys=True) for key in expected}
        require(len(resources) >= 2, "fixture must contain at least two resources")
        output = directory / "output.jsonl"
        metric_output = directory / "metrics-output.jsonl"
        config = directory / "collector.yaml"
        config.write_text(f"""receivers:
  otlpjsonfile:
    include: [{json.dumps(str(directory / "logs*.jsonl"))}]
    start_at: beginning
    include_file_name: false
  otlpjsonfile/metrics:
    include: [{json.dumps(str(directory / "metrics.jsonl"))}]
    start_at: beginning
    include_file_name: false
exporters:
  file/metrics:
    path: {json.dumps(str(metric_output))}
  file:
    path: {json.dumps(str(output))}
service:
  pipelines:
    metrics:
      receivers: [otlpjsonfile/metrics]
      exporters: [file/metrics]
    logs:
      receivers: [otlpjsonfile]
      exporters: [file]
""")
        with (directory / "collector.log").open("w+") as log:
            child = subprocess.Popen(
                ["otelcol-contrib", "--config", str(config)], stdout=log, stderr=log
            )
            try:
                deadline = time.monotonic() + 60
                stable_since = time.monotonic()
                previous = -1
                while time.monotonic() < deadline:
                    require(child.poll() is None, "Collector exited early")
                    # Poll byte length: an in-progress write may end mid UTF-8 scalar.
                    size = output.stat().st_size if output.exists() else 0
                    if size != previous:
                        previous, stable_since = size, time.monotonic()
                    if size > 0 and time.monotonic() - stable_since >= 2:
                        break
                    time.sleep(0.25)
                else:
                    raise AssertionError("Collector output did not stabilize")
            finally:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                log.seek(0)
                print(log.read())
        expected_metrics = metric_points(
            json.loads(line)
            for line in json_lines((directory / "metrics.jsonl").read_text())
        )
        actual_metrics = metric_points(
            json.loads(line) for line in json_lines(metric_output.read_text())
        )
        require(sum(expected_metrics.values()) == 41, "missing metric fixture points")
        require(
            actual_metrics == expected_metrics,
            f"Metric differences: {expected_metrics - actual_metrics}; unexpected: {actual_metrics - expected_metrics}",
        )
        require(
            any(
                json.loads(key)[2]["name"] == "conformance.kept"
                for key in actual_metrics
            ),
            "Collector lost the healthy metric from the poisoned run",
        )
        require(
            all(
                json.loads(key)[2]["name"] != "conformance.conflict"
                for key in actual_metrics
            ),
            "Collector received a poisoned name",
        )
        actual = records(json.loads(line) for line in json_lines(output.read_text()))
        require(
            actual == expected,
            f"Lost/changed: {expected - actual}\nUnexpected: {actual - expected}",
        )
        print(
            f"Conformant: {sum(actual.values())} records including {len(writer_lines)} generated writer cases across {len(list(directory.glob('logs*.jsonl')))} input files; valid EOF delivered, garbage EOF dropped"
        )
    # TODO: extend reference-reader conformance to traces (#8).


if __name__ == "__main__":
    main()

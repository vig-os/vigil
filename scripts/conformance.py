"""Compare vigil output by meaning using the pinned Collector as reference reader."""

import collections
import json
import pathlib
import subprocess
import tempfile
import time


def normalize(value):
    """Preserve AnyValue tags; only protobuf message defaults may disappear."""
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in ("intValue", "timeUnixNano", "observedTimeUnixNano"):
            item = str(int(item))
        if key == "doubleValue" and isinstance(item, (int, float)):
            item = float(item) if item != 0 else 0.0
        if key in ("traceId", "spanId") and item:
            assert len(item) == {"traceId": 32, "spanId": 16}[key]
            assert all(char in "0123456789abcdefABCDEF" for char in item)
            item = item.lower()
        # AnyValue scalar defaults retain their type and must never be erased.
        if not key.endswith("Value") and item in (0, "0", "", [], {}, None):
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


def main():
    subprocess.run(["otelcol-contrib", "--version"], check=True)
    with tempfile.TemporaryDirectory(prefix="vigil-conformance-") as temporary:
        directory = pathlib.Path(temporary)
        subprocess.run(
            ["cargo", "run", "--locked", "--example", "conformance", "--", temporary],
            check=True,
        )
        inputs = sorted(directory.glob("logs*.jsonl"))
        assert len(inputs) > 1, "rotation did not happen"
        # Empty lines and terminated garbage between valid neighbouring batches.
        lines = inputs[0].read_text().splitlines()
        assert lines
        neighbour = inputs[1].read_text()
        inputs[0].write_text("\n" + "\n".join(lines) + "\n\ngarbage\n\n" + neighbour)
        inputs[1].write_text("")
        expected = records(json.loads((directory / "manifest.json").read_text()))
        output = directory / "output.jsonl"
        config = directory / "collector.yaml"
        config.write_text(f"""receivers:
  otlpjsonfile:
    include: [{json.dumps(str(directory / "logs*.jsonl"))}]
    start_at: beginning
    include_file_name: false
exporters:
  file:
    path: {json.dumps(str(output))}
service:
  pipelines:
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
                    assert child.poll() is None, "Collector exited early"
                    text = output.read_text() if output.exists() else ""
                    count = len(text.splitlines())
                    if count != previous:
                        previous, stable_since = count, time.monotonic()
                    if count > 0 and time.monotonic() - stable_since >= 2:
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
        actual = records(json.loads(line) for line in output.read_text().splitlines())
        assert actual == expected, (
            f"Lost/changed: {expected - actual}\nUnexpected: {actual - expected}"
        )
        print(
            f"Conformant: {sum(actual.values())} records across {len(inputs)} rotated files"
        )
    # TODO: extend reference-reader conformance to metrics (#7) and traces (#8).


if __name__ == "__main__":
    main()

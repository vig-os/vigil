"""Real Collector → Prometheus oracle for ADR-0003 d12/d21.

Rows the facade rejects (d24) are checked against the translator only.
The Rust exclusion guard proves that no accepted name can bypass this path.
"""

import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOUNDARIES = [
    0,
    5,
    10,
    25,
    50,
    75,
    100,
    250,
    500,
    750,
    1000,
    2500,
    5000,
    7500,
    10000,
    float("inf"),
]


def require(condition, message):
    """Checks remain active under python -O."""
    if not condition:
        raise AssertionError(message)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def query(port, expression):
    url = f"http://127.0.0.1:{port}/api/v1/query?" + urllib.parse.urlencode(
        {"query": expression}
    )
    with urllib.request.urlopen(url, timeout=2) as response:
        data = json.load(response)
    require(data["status"] == "success", f"query failed: {data}")
    return data["data"]["result"]


def canonical(metric):
    """Compare numeric bucket boundaries, including +Inf, independently of spelling."""
    return tuple(
        sorted(
            (key, float(value) if key == "le" else value)
            for key, value in metric.items()
        )
    )


def series(names, kind, scope, version, instance, job, value=7):
    result = {}
    for name in names:
        labels = dict(
            __name__=name,
            instance=instance,
            job=job,
            otel_scope_name=scope,
            otel_scope_version=version,
        )
        if kind == "Histogram" and name.endswith("_bucket"):
            for bound in BOUNDARIES:
                result[canonical(labels | {"le": bound})] = 0 if bound == 0 else 2
        else:
            expected = 2 if kind == "Histogram" and name.endswith("_count") else value
            result[canonical(labels)] = 4 if kind == "Gauge" else expected
    return result


def run_case(binary, directory, case, rows):
    destination = directory / case
    child = subprocess.run(
        [str(binary), case, str(destination)], capture_output=True, text=True
    )
    poisoned = case in ("S2", "S3", "S4", "S4b", "S5")
    require(
        child.returncode == (2 if poisoned else 0),
        f"{case}: exit {child.returncode}\n{child.stderr}",
    )
    diagnostics = [
        line
        for line in child.stderr.splitlines()
        if line.startswith("vigil: conflicting metric instruments:")
    ]
    informational = [
        line
        for line in child.stderr.splitlines()
        if "Prometheus needs otlp.promote_scope_metadata: true" in line
    ]
    require(len(diagnostics) == int(poisoned), f"{case}: diagnostics: {child.stderr}")
    require(
        len(informational) == int(case == "S1"),
        f"{case}: informational: {child.stderr}",
    )
    if case == "S1":
        require("crate-a@1 and crate-b@1" in informational[0], child.stderr)
    for operation in ("flush", "shutdown"):
        require(
            f"vigil-conformance: {operation}: {'DataLost:' if poisoned else 'OK'}"
            in child.stderr,
            f"{case}: unexpected {operation}: {child.stderr}",
        )
    lines = (destination / "metrics.jsonl").read_text().splitlines()
    require(len(lines) == 2, f"{case}: expected two exports, got {len(lines)}")
    messages = [json.loads(line) for line in lines]
    attrs = messages[-1]["resourceMetrics"][0]["resource"]["attributes"]
    resource = {a["key"]: a["value"] for a in attrs}
    instance = resource["service.instance.id"]["stringValue"]
    job = resource["service.name"]["stringValue"]
    package_name, package_version = json.loads((destination / "scope.json").read_text())
    version = package_version if case == "clean" or case.startswith("fixture-") else "1"
    stamps = [
        int(line.rsplit(": ", 1)[1])
        for line in child.stderr.splitlines()
        if " timeUnixNano: " in line
    ]
    require(
        len(stamps) == 2 and stamps[1] // 1_000_000 > stamps[0] // 1_000_000,
        f"{case}: export timestamps do not advance: {stamps}",
    )
    print(f"{case}: timeUnixNano {stamps[0]} → {stamps[1]}", flush=True)
    expected = {}

    def add(names, kind="Counter", scope="crate-a", value=7):
        expected.update(series(names, kind, scope, version, instance, job, value))

    if poisoned:
        add(["app_witness_total"], value=2)
    elif case in ("S1", "S1b"):
        add(["app_x_total"], value=10 if case == "S1" else 7)
        add(["app_x_total"], scope="crate-b", value=14 if case == "S1" else 7)
    elif case == "clean":
        add(["app_requests_total"], scope=package_name)
        add(
            [
                "app_latency_milliseconds_" + suffix
                for suffix in ("bucket", "sum", "count")
            ],
            "Histogram",
            package_name,
        )
        add(["app_memory_bytes"], "Gauge", package_name)
    else:
        row = rows[int(case.removeprefix("fixture-"))]
        add(row["expected"], row["kind"], package_name)
    return case, instance, job, expected


def start_servers(directory, children):
    """Retry a bind race once, using fresh free ports and fresh TSDB storage."""
    for attempt in range(2):
        port = free_port()
        config = directory / f"prometheus-{attempt}.json"
        config.write_text(json.dumps({"otlp": {"promote_scope_metadata": True}}))
        log_path = directory / f"prometheus-{attempt}.log"
        with log_path.open("w") as log:
            prom = subprocess.Popen(
                [
                    "prometheus",
                    "--web.enable-otlp-receiver",
                    f"--web.listen-address=127.0.0.1:{port}",
                    f"--config.file={config}",
                    f"--storage.tsdb.path={directory / f'tsdb-{attempt}'}",
                ],
                stdout=log,
                stderr=log,
            )
        children.append(prom)
        deadline = time.monotonic() + 60
        while prom.poll() is None and time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/-/ready", timeout=1
                ) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.25)
        else:
            text = log_path.read_text()
            stop(prom)
            if attempt == 0 and "address already in use" in text:
                continue
            raise AssertionError(f"Prometheus failed to become ready:\n{text}")
        collector_config = directory / "collector.json"
        collector_config.write_text(
            json.dumps(
                {
                    "receivers": {
                        "otlpjsonfile": {
                            "include": [str(directory / "*" / "metrics.jsonl")],
                            "start_at": "beginning",
                            "include_file_name": False,
                        }
                    },
                    "exporters": {
                        "otlp_http": {
                            "endpoint": f"http://127.0.0.1:{port}/api/v1/otlp"
                        }
                    },
                    "service": {
                        "telemetry": {"metrics": {"level": "none"}},
                        "pipelines": {
                            "metrics": {
                                "receivers": ["otlpjsonfile"],
                                "exporters": ["otlp_http"],
                            }
                        },
                    },
                }
            )
        )
        collector_log = directory / "collector.log"
        with collector_log.open("w") as log:
            collector = subprocess.Popen(
                ["otelcol-contrib", "--config", str(collector_config)],
                stdout=log,
                stderr=log,
            )
        children.append(collector)
        # Telemetry is disabled; the Collector binds no ports and needs no retry.
        return port, prom, collector
    raise AssertionError("Prometheus bind retries exhausted")


def main():
    for command in ("prometheus", "otelcol-contrib"):
        require(shutil.which(command), f"missing required binary: {command}")
        subprocess.run([command, "--version"], check=True)
    env = os.environ.copy()
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    build_start = time.monotonic()
    subprocess.run(
        ["cargo", "build", "--locked", "--example", "prometheus_conformance"],
        cwd=ROOT,
        env=env,
        check=True,
    )
    print(f"Build: {time.monotonic() - build_start:.2f}s", flush=True)
    target = pathlib.Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    binary = target.resolve() / "debug/examples/prometheus_conformance"
    rows = json.loads((ROOT / "tests/fixtures/prometheus_names.json").read_text())
    cases = ["S1", "S1b", "S2", "S3", "S4", "S4b", "S5", "clean"]
    cases += [
        f"fixture-{i}" for i, row in enumerate(rows) if "translation_only" not in row
    ]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="vigil-prometheus-") as temporary:
        directory = pathlib.Path(temporary)
        expected_runs = [run_case(binary, directory, case, rows) for case in cases]
        require(
            len({run[1] for run in expected_runs}) == len(expected_runs),
            "instance IDs must be distinct",
        )
        children = []
        try:
            port, prom, collector = start_servers(directory, children)
            deadline = time.monotonic() + 60
            pending = expected_runs.copy()
            observed = {}
            while pending and time.monotonic() < deadline:
                require(
                    prom.poll() is None, (directory / "prometheus-0.log").read_text()
                )
                require(
                    collector.poll() is None, (directory / "collector.log").read_text()
                )
                remaining = []
                for run in pending:
                    case, instance, job, expected = run
                    values = query(
                        port, f'{{instance="{instance}",__name__!="target_info"}}'
                    )
                    actual = {
                        canonical(row["metric"]): float(row["value"][1])
                        for row in values
                    }
                    target = query(port, f'target_info{{instance="{instance}"}}')
                    if (
                        all(actual.get(key) == value for key, value in expected.items())
                        and target
                    ):
                        observed[case] = (actual, target)
                    else:
                        remaining.append(run)
                pending = remaining
                if pending:
                    time.sleep(0.25)
            require(
                not pending,
                f"final values missing after 60s: {[run[0] for run in pending]}\nCollector:\n{(directory / 'collector.log').read_text()}",
            )
            # All runs, including poison witnesses, have reached final values.
            # Only now assert exact sets, so absences cannot pass before ingestion.
            for case, instance, job, expected in expected_runs:
                actual, target = observed[case]
                require(
                    actual == expected,
                    f"{case}: exact series/value mismatch:\nexpected {expected}\nactual {actual}",
                )
                require(
                    len(target) == 1 and target[0]["metric"].get("job") == job,
                    f"{case}: target_info {target}",
                )
                print(f"{case}: OK", flush=True)
        finally:
            for child in reversed(children):
                stop(child)
    print(f"Run: {time.monotonic() - started:.2f}s; OK", flush=True)


if __name__ == "__main__":
    main()

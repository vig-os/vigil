#!/usr/bin/env python3
"""Compare Criterion mean elapsed times to a reviewed, committed baseline."""

import argparse
import json
import math
import os
from pathlib import Path

BENCHMARKS = {
    "append/1_processes": 4096,
    "append/8_processes": 32768,
    "init/pipeline": 1,
    "export/pipeline": 4096,
    "split/pipeline": 4096,
    "rotation/100": 1,
    "rotation/1000": 1,
    "rotation/10000": 1,
}
THRESHOLD = 2.0


def read_estimates(root):
    """Require every workload; missing measurements must never look green."""
    values = {}
    for name in BENCHMARKS:
        path = root / name / "new" / "estimates.json"
        value = json.loads(path.read_text())["mean"]["point_estimate"]
        if (
            not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"Invalid mean for {name}: {value}")
        values[name] = value
    return values


def report(current, baseline):
    """Return a Markdown report and whether any elapsed-time ratio is >= 2."""
    lines = [
        "## Performance (advisory)",
        "",
        f"Flag threshold: elapsed time >= {THRESHOLD:g}x committed baseline.",
        "Shared runners vary; confirm on baseline hardware before acting.",
        "",
        "| Workload | Mean ms | Records/s or ops/s | Baseline ratio | Status |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    regression = False
    for name, records in BENCHMARKS.items():
        before = baseline[name]
        if (
            not isinstance(before, (int, float))
            or not math.isfinite(before)
            or before <= 0
        ):
            raise ValueError(f"Invalid baseline for {name}: {before}")
        ratio = current[name] / before
        flagged = ratio >= THRESHOLD
        regression |= flagged
        status = "REGRESSION — investigate" if flagged else "within threshold"
        lines.append(
            f"| {name} | {current[name] / 1e6:.3f} | "
            f"{records * 1e9 / current[name]:.0f} | {ratio:.2f}x | {status} |"
        )
    return "\n".join(lines) + "\n", regression


def main():
    """Report advisory results or explicitly replace a reviewed baseline."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=Path("benches/baseline.json"))
    parser.add_argument("--update", action="store_true")
    parser.add_argument(
        "--environment", help="Hardware/OS/toolchain/storage for baseline update"
    )
    args = parser.parse_args()
    try:
        current = read_estimates(args.results)
        if args.update:
            if not args.environment:
                parser.error("--update requires --environment")
            args.baseline.write_text(
                json.dumps(
                    {
                        "environment": args.environment,
                        "mean_ns": current,
                    },
                    indent=2,
                )
                + "\n"
            )
            return
        baseline = json.loads(args.baseline.read_text())
        output, regression = report(current, baseline["mean_ns"])
    except (OSError, ValueError, KeyError, TypeError) as error:
        output = f"## Performance (advisory)\n\nMeasurement unavailable: {error}\n"
        print(output)
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a") as file:
                file.write(output)
        raise SystemExit(1) from error
    print(output)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as file:
            file.write(output)
    if regression:
        print(
            "::warning::Performance >= 2x baseline; repeat on reference hardware and investigate."
        )
    # Regressions are advisory. Broken measurement is distinct and exits 1.


if __name__ == "__main__":
    main()

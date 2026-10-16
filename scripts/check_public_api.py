"""Freeze the stable surface and enforce ADR-0004, including hidden exports."""

import argparse
import difflib
import json
from pathlib import Path
import re
import subprocess

from check_semver import stable_environment

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_CRATES = {
    "core",
    "alloc",
    "std",
    "tracing",
    "tracing_core",
    "tracing_subscriber",
}


def own_paths(listing):
    """Extract item/member paths, removing generic arguments for lookup."""
    simplified = listing
    while re.search(r"<[^<>]*>", simplified):
        simplified = re.sub(r"<[^<>]*>", "", simplified)
    pattern = r"\bvigil(?:::[A-Za-z_][A-Za-z_0-9]*)*"
    return set(re.findall(pattern, listing)) | set(re.findall(pattern, simplified))


def item_kinds(listing):
    """Read declared kinds separately from paths mentioned in signatures/impls."""
    declarations = {}
    for line in listing.splitlines():
        line = re.sub(r"^(?:#\[[^\]]+\]\s*)+", "", line)
        if not line.startswith("pub "):
            continue
        line = re.sub(r"^pub const fn ", "pub fn ", line)
        match = re.match(
            r"pub (?:(mod|struct|enum|trait|fn|const|static|type|macro|extern crate) )?"
            r"(vigil(?:::[A-Za-z_][A-Za-z_0-9]*)*)",
            line,
        )
        if not match:
            raise ValueError(f"Unrecognized public item declaration: {line}")
        kind, path = match.groups()
        declarations.setdefault(path, set()).add(kind or "variant")
    return declarations


def validate(listing, document, allowed):
    """Reject empty listings, unjustified items and forbidden dependency paths."""
    if "pub mod vigil\n" not in listing or len(own_paths(listing)) < 2:
        raise ValueError("Public API listing is empty or lacks the crate root")
    foreign = {
        crate["name"] for crate in document["external_crates"].values()
    } - ALLOWED_CRATES
    for name in sorted(foreign):
        if re.search(rf"\b{re.escape(name)}::", listing):
            raise ValueError(f"Forbidden upstream crate in stable API: {name}")
    if "__private" in listing:
        raise ValueError("Private macro re-export paths are forbidden")
    # A whole-crate re-export can be rendered without a qualified type path.
    # Resolve public use targets directly as well as checking the listing.
    for item in document["index"].values():
        use = item["inner"].get("use")
        if item["visibility"] == "public" and use and use["id"] is not None:
            target = document["paths"].get(str(use["id"]))
            if target and target["crate_id"] != 0:
                crate = document["external_crates"][str(target["crate_id"])]["name"]
                if crate not in ALLOWED_CRATES:
                    raise ValueError(f"Forbidden upstream re-export: {crate}")

    for item in document["index"].values():
        external = item["inner"].get("extern_crate")
        if item["visibility"] == "public" and external:
            # The pinned rustdoc records the exported alias in `name` and
            # its original crate name in `rename` (None when unaliased).
            crate = (external.get("rename") or external["name"]).replace("-", "_")
            if crate not in ALLOWED_CRATES:
                raise ValueError(f"Forbidden public extern crate: {crate}")

    for path, kinds in item_kinds(listing).items():
        if path in allowed and kinds != {allowed[path]}:
            raise ValueError(
                f"Item kind mismatch for {path}: {sorted(kinds)}; expected {allowed[path]}"
            )
    unknown = own_paths(listing) - allowed.keys()
    if unknown:
        raise ValueError(
            f"Items need ADR justification in api/allowlist.json: {sorted(unknown)}"
        )


def generate(hidden, env):
    """Build JSON on the pinned compiler, then ask cargo-public-api to list it."""
    command = [
        "cargo",
        "rustdoc",
        "--locked",
        "--lib",
        "--all-features",
        "--",
        "-Z",
        "unstable-options",
        "--output-format",
        "json",
    ]
    if hidden:
        command.append("--document-hidden-items")
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=ROOT,
            env=env,
            text=True,
        )
    )
    path = Path(metadata["target_directory"]) / "doc/vigil.json"
    document = json.loads(path.read_text())
    listing = subprocess.check_output(
        [
            "cargo",
            "public-api",
            "--rustdoc-json",
            str(path),
            "-sss",
            "--color",
            "never",
        ],
        cwd=ROOT,
        env=env,
        text=True,
    )
    return listing, document


def main():
    """Check both surfaces before allowing snapshot verification or an update."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update", action="store_true", help="write the reviewed snapshot"
    )
    args = parser.parse_args()
    allowed = {}
    for section in json.loads((ROOT / "api/allowlist.json").read_text()):
        if not section["justification"]:
            raise ValueError("Every allowlist group needs an ADR justification")
        allowed.update(section["items"])
    env = stable_environment()
    env["RUSTC_BOOTSTRAP"] = "1"
    env["CARGO_TERM_COLOR"] = "never"
    normal, document = generate(False, env)
    validate(normal, document, allowed)
    hidden, document = generate(True, env)
    validate(hidden, document, allowed)
    snapshot = ROOT / "api/public-api.txt"
    if args.update:
        snapshot.write_text(hidden)
    elif snapshot.read_text() != hidden:
        print(
            "".join(
                difflib.unified_diff(
                    snapshot.read_text().splitlines(True),
                    hidden.splitlines(True),
                    fromfile=str(snapshot),
                    tofile="current public API",
                )
            )
        )
        raise SystemExit(
            "Public API changed: review the ADR allowlist, then run --update"
        )
    print(
        f"Stable API: {len(hidden.splitlines())} snapshot lines; visible and hidden allowlists pass"
    )


if __name__ == "__main__":
    main()

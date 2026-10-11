"""Exercise non-vacuity, ADR membership and upstream paths in both listings."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_public_api

from check_public_api import own_paths, validate


class PublicApiTests(unittest.TestCase):
    def setUp(self):
        self.allowed = {"vigil", "vigil::Config", "vigil::Config::layer"}
        self.document = {
            "external_crates": {"1": {"name": "opentelemetry"}, "2": {"name": "bytes"}},
            "index": {},
            "paths": {},
        }
        self.listing = "pub mod vigil\npub struct vigil::Config\n"

    def test_empty_and_root_only_fail(self):
        for listing in ("", "\n", "pub mod vigil\n"):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                validate(listing, self.document, self.allowed)

    def test_known_api_and_argument_named_like_crate(self):
        validate(self.listing, self.document, self.allowed)
        validate(
            self.listing + "pub fn vigil::Config::layer(bytes: &[u8])\n",
            self.document,
            self.allowed,
        )

    def test_new_owned_item_needs_adr_even_with_updated_snapshot(self):
        with self.assertRaisesRegex(ValueError, "ADR justification"):
            validate(
                self.listing + "pub fn vigil::unjustified()\n",
                self.document,
                self.allowed,
            )

    def test_generic_method_is_individually_checked(self):
        self.assertIn(
            "vigil::Config::layer", own_paths("pub fn vigil::Config::layer<S>()")
        )
        with self.assertRaisesRegex(ValueError, "ADR justification"):
            validate(
                self.listing + "pub fn vigil::Config::extra<T>()\n",
                self.document,
                self.allowed,
            )

    def test_generic_bounds_cannot_hide_unjustified_owned_types(self):
        self.assertIn(
            "vigil::PrivateTrait",
            own_paths("pub fn vigil::Config::layer<S: vigil::PrivateTrait>()"),
        )

    def test_upstream_signature_fails(self):
        with self.assertRaisesRegex(ValueError, "Forbidden upstream crate"):
            validate(
                self.listing
                + "pub fn vigil::Config::layer(_: opentelemetry::KeyValue)\n",
                self.document,
                self.allowed,
            )

    def test_hidden_crate_reexport_with_alias_fails_without_qualified_path(self):
        self.document["index"]["9"] = {
            "visibility": "public",
            "inner": {"use": {"id": 10}},
        }
        self.document["paths"]["10"] = {"crate_id": 1}
        with self.assertRaisesRegex(ValueError, "Forbidden upstream re-export"):
            validate(self.listing, self.document, self.allowed)

    def test_private_macro_path_fails(self):
        with self.assertRaisesRegex(ValueError, "Private macro"):
            validate(
                self.listing + "pub mod vigil::__private\n",
                self.document,
                self.allowed | {"vigil::__private"},
            )


if __name__ == "__main__":
    unittest.main()


class SnapshotTests(unittest.TestCase):
    def test_changed_signature_requires_snapshot_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "api").mkdir()
            (root / "api/allowlist.json").write_text(
                json.dumps(
                    [
                        {
                            "justification": "ADR-0004",
                            "items": ["vigil", "vigil::init"],
                        }
                    ]
                )
            )
            old = "pub mod vigil\npub fn vigil::init()\n"
            new = "pub mod vigil\npub fn vigil::init(_: bool)\n"
            (root / "api/public-api.txt").write_text(old)
            document = {"index": {}, "paths": {}, "external_crates": {}}
            with (
                patch.object(check_public_api, "ROOT", root),
                patch.object(
                    check_public_api, "generate", return_value=(new, document)
                ),
                patch("sys.argv", ["check_public_api.py"]),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(SystemExit, "Public API changed"),
            ):
                check_public_api.main()

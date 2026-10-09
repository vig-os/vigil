"""Guard semantic normalization against hiding meaningful changes."""

import copy
import unittest

from conformance import normalize, records


class ComparisonTests(unittest.TestCase):
    def test_defaults_and_numeric_spellings(self):
        self.assertEqual(normalize({"severityNumber": 0, "traceId": ""}), {})
        self.assertEqual(normalize({"intValue": 42}), {"intValue": "42"})
        self.assertEqual(normalize({"doubleValue": -0.0}), {"doubleValue": 0.0})
        self.assertEqual(normalize({"name": "0"}), {"name": "0"})
        self.assertNotEqual(normalize({"intValue": 0}), normalize({"boolValue": False}))
        self.assertNotEqual(normalize({"stringValue": ""}), {})
        self.assertNotEqual(normalize({"arrayValue": {}}), {})

    def test_loss_duplicates_and_changed_fields(self):
        record = {
            "body": {"stringValue": "body"},
            "attributes": [{"key": "a", "value": {"intValue": "42"}}],
            "severityNumber": 9,
            "severityText": "INFO",
            "timeUnixNano": "123",
            "observedTimeUnixNano": "124",
            "traceId": "12" * 16,
            "spanId": "34" * 8,
            "flags": 1,
        }
        message = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "test"}}
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "scope", "version": "1"},
                            "logRecords": [record],
                        }
                    ],
                }
            ]
        }
        expected = records([message])
        self.assertNotEqual(expected, records([]))
        self.assertNotEqual(expected, records([message, message]))
        for field in record:
            changed = copy.deepcopy(message)
            del changed["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0][field]
            self.assertNotEqual(expected, records([changed]), field)
        for field in ("resource", "scope"):
            changed = copy.deepcopy(message)
            if field == "resource":
                changed["resourceLogs"][0]["resource"] = {}
            else:
                changed["resourceLogs"][0]["scopeLogs"][0]["scope"] = {}
            self.assertNotEqual(expected, records([changed]), field)
        with self.assertRaises(AssertionError):
            normalize({"traceId": "1234"})


if __name__ == "__main__":
    unittest.main()

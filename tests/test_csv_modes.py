"""Unified/default, split and filtered CSV exports using synthetic inputs."""
import argparse
import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_conversion as base


class CsvModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oci-csv-modes-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def export(self, rules=None, *, split=False, only=None, output=None, force=False):
        ingress = self.work / "input-ingress.json"
        egress = self.work / "input-egress.json"
        rules = rules or {"ingress": [], "egress": []}
        for path, direction in ((ingress, "ingress"), (egress, "egress")):
            path.write_text(json.dumps(rules[direction]), encoding="utf-8")
        args = argparse.Namespace(ingress=ingress, egress=egress, oci_get=None,
                                  split=split, only=only, force=force,
                                  output_dir=output or self.work / "csv")
        with contextlib.redirect_stdout(io.StringIO()):
            count = base.JSON_TO_CSV.export_csv(args)
        return args.output_dir, count

    def rows(self, directory, name="rules"):
        with (directory / (name + ".csv")).open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    def imported(self, directory, output=None):
        output = output or self.work / "json"
        with contextlib.redirect_stdout(io.StringIO()):
            base.CSV_TO_JSON.convert_all(directory, output, False)
        return {direction: base.rule_meanings(json.loads((output / (direction + ".json")).read_text(encoding="utf-8")))
                for direction in ("ingress", "egress")}

    def fixtures(self):
        rules = {"ingress": [], "egress": []}
        for direction in rules:
            for code in ("6", "17", "1", "all"):
                rules[direction].extend([base.make_rule(direction, code),
                                         base.make_service_rule(direction, code)])
        return rules

    def test_default_single_csv_round_trip_all_purposes_and_directions(self):
        rules = self.fixtures()
        output, count = self.export(rules)
        self.assertEqual(count, 0)
        self.assertEqual(sorted(p.name for p in output.iterdir()), ["rules.csv", "unconverted-rules.json"])
        self.assertTrue((output / "rules.csv").read_bytes().startswith(b"\xef\xbb\xbf"))
        rows = self.rows(output)
        self.assertEqual(len(rows), 16)
        self.assertEqual(list(rows[0]), base.JSON_TO_CSV.COMBINED_FIELDS)
        self.assertEqual({row["address_type"] for row in rows}, {"CIDR_BLOCK", "SERVICE_CIDR_BLOCK"})
        self.assertEqual(self.imported(output), rules)

    def test_combined_example_matches_json_examples(self):
        expected = {direction: base.rule_meanings(json.loads((base.ROOT / "examples/json" / (direction + ".json")).read_text(encoding="utf-8")))
                    for direction in ("ingress", "egress")}
        self.assertEqual(self.imported(base.ROOT / "examples/combined"), expected)

    def test_default_empty_writes_only_header_and_complete_report(self):
        output, count = self.export()
        self.assertEqual(count, 0)
        self.assertEqual(self.rows(output), [])
        self.assertEqual(self.imported(output), {"ingress": [], "egress": []})

    def test_nulls_and_literal_null_escape_round_trip_in_both_modes(self):
        descriptions = [None, "", "NULL", "\\NULL", "\\other", '  説明, "引用"\n次行  ']
        for split in (False, True):
            rules = {"ingress": [base.make_rule("ingress", "6", description=text) for text in descriptions],
                     "egress": [base.make_rule("egress", "1", icmpOptions={"type": 8, "code": None}),
                                base.make_service_rule("egress", "all", "NULL"),
                                base.make_service_rule("egress", "all", "\\label")]}
            output, _ = self.export(rules, split=split, output=self.work / str(split))
            rows = self.rows(output, "tcp" if split else "rules")
            self.assertEqual(rows[0]["description"], "NULL")
            self.assertEqual(rows[1]["description"], "")
            self.assertEqual(rows[2]["description"], "\\NULL")
            self.assertEqual(rows[0]["dst_min"], "NULL")
            self.assertEqual(rows[0]["dst_max"], "NULL")
            if not split:
                self.assertEqual((rows[6]["dst_min"], rows[6]["code"]), ("NULL", "NULL"))
                self.assertEqual(rows[6]["type"], "8")
            expected = base.rule_meanings(rules)
            for rule in expected["ingress"]:
                if rule.get("description") == "":
                    del rule["description"]
            self.assertEqual(self.imported(output, self.work / ("json-" + str(split))), expected)

    def test_split_outputs_five_csvs_and_round_trips(self):
        rules = self.fixtures()
        output, _ = self.export(rules, split=True)
        self.assertEqual(sorted(p.stem for p in output.glob("*.csv")), ["all", "icmp", "service", "tcp", "udp"])
        self.assertEqual(len(self.rows(output, "service")), 8)
        self.assertEqual(len(self.rows(output, "tcp")), 2)
        self.assertEqual(self.imported(output), rules)

    def test_only_exports_requested_purposes_without_service_duplication(self):
        for selection in (["tcp"], ["service"], ["tcp", "service"]):
            output, count = self.export(self.fixtures(), only=selection,
                                        output=self.work / "-".join(selection))
            self.assertEqual(count, 0)
            self.assertEqual(sorted(p.stem for p in output.glob("*.csv")), sorted(selection))
            expected_count = sum(8 if name == "service" else 2 for name in selection)
            self.assertEqual(sum(len(self.rows(output, name)) for name in selection), expected_count)
            report = json.loads((output / "unconverted-rules.json").read_text())
            self.assertEqual(report["selected_purposes"], selection)
            self.assertEqual(report["excluded_count"], 16 - expected_count)
            self.assertEqual(report["status"], "complete")
            with self.assertRaisesRegex(ValueError, "除外"):
                self.imported(output)

    def test_only_with_no_matching_rules_still_outputs_header(self):
        output, _ = self.export({"ingress": [base.make_rule("ingress", "6")], "egress": []}, only=["udp"])
        self.assertEqual(self.rows(output, "udp"), [])
        self.assertFalse((output / "tcp.csv").exists())

    def test_default_partial_report_preserves_raw_rule_and_blocks_import(self):
        raw = base.hyphen_keys(base.make_rule("egress", "58"))
        output, count = self.export({"ingress": [base.make_rule("ingress", "6")], "egress": [raw]})
        self.assertEqual(count, 1)
        self.assertEqual(len(self.rows(output)), 1)
        report = json.loads((output / "unconverted-rules.json").read_text())
        self.assertEqual(report["egress"][0]["rule"], raw)
        with self.assertRaises(ValueError):
            self.imported(output)

    def test_overwrite_and_mixed_mode_guards(self):
        output, _ = self.export(self.fixtures())
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        with self.assertRaises(ValueError):
            self.export(output=output)
        with self.assertRaises(ValueError):
            self.export(output=output, split=True, force=True)
        self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)
        self.export(output=output, force=True)
        self.assertEqual(self.rows(output), [])
        (output / "tcp.csv").write_text("sentinel", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "混在"):
            self.imported(output)

    def test_unified_import_rejects_invalid_protocol_unused_values_and_one_null_port(self):
        output, _ = self.export(self.fixtures())
        rows = self.rows(output)
        for field, value in (("protocol", "58"), ("type", "8"), ("dst_min", "443"), ("stateless", "NULL")):
            bad = dict(rows[0], **{field: value})
            with (output / "rules.csv").open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=base.JSON_TO_CSV.COMBINED_FIELDS)
                writer.writeheader()
                writer.writerow(bad)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.imported(output)
            self.assertFalse((self.work / "json").exists())

    def test_cli_default_split_only_and_invalid_options(self):
        for options, expected in (([], ["rules"]), (["--split"], ["all", "icmp", "service", "tcp", "udp"]),
                                  (["--only", "tcp", "service"], ["service", "tcp"]),
                                  (["--only", "udp"], ["udp"])):
            output = self.work / ("cli-" + "-".join(options or ["default"]))
            command = [sys.executable, str(base.ROOT / "oci_security_list_json_to_csv.py"),
                       "--oci-get", str(base.ROOT / "examples/oci-get.json"), "--output-dir", str(output), *options]
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sorted(p.stem for p in output.glob("*.csv")), expected)
        for index, options in enumerate((["--split", "--only", "tcp"], ["--only", "unknown"], ["--only"])):
            output = self.work / ("bad-cli-" + str(index))
            result = subprocess.run([sys.executable, str(base.ROOT / "oci_security_list_json_to_csv.py"),
                                     "--oci-get", str(base.ROOT / "examples/oci-get.json"),
                                     "--output-dir", str(output), *options], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertEqual(list(output.glob("*.csv")), [])


if __name__ == "__main__":
    unittest.main()

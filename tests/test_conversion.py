"""Round-trip and fail-closed tests; fixtures contain documentation addresses only."""

import argparse
import contextlib
import csv
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CSV_TO_JSON = load_module("oci_security_list_csv_to_json")
JSON_TO_CSV = load_module("oci_security_list_json_to_csv")


def make_rule(direction, protocol_code, **extra):
    address = "source" if direction == "ingress" else "destination"
    address_type = "sourceType" if direction == "ingress" else "destinationType"
    rule = {"protocol": protocol_code, address: "192.0.2.0/24",
            address_type: "CIDR_BLOCK", "isStateless": False}
    rule.update(extra)
    return rule


def hyphen_keys(value):
    """Build a fixture in the spelling used by OCI CLI get output."""
    if isinstance(value, dict):
        return {"".join("-" + c.lower() if c.isupper() else c for c in key):
                hyphen_keys(item) for key, item in value.items()}
    if isinstance(value, list):
        return [hyphen_keys(item) for item in value]
    return value


class ConversionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-")
        self.work = Path(self.temporary.name)
        self.addCleanup(self.cleanup_workspace)

    def cleanup_workspace(self):
        # Verify the generated workspace before recursively removing it.
        if self.work.resolve().parent != ROOT.resolve() or not self.work.name.startswith(".test-"):
            raise RuntimeError("Unexpected temporary test directory")
        self.temporary.cleanup()

    def write_json(self, name, data):
        path = self.work / name
        path.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8")
        return path

    def export(self, ingress=None, egress=None, output=None, force=False, get=None):
        args = argparse.Namespace(oci_get=get, ingress=None, egress=None,
                                  output_dir=output or self.work / "csv", force=force)
        if get is None:
            args.ingress = self.write_json("ingress-input.json", ingress or [])
            args.egress = self.write_json("egress-input.json", egress or [])
        with contextlib.redirect_stdout(io.StringIO()):
            JSON_TO_CSV.export_csv(args)
        return args.output_dir

    def import_csv(self, directory, output=None, force=False):
        output = output or self.work / "json"
        with contextlib.redirect_stdout(io.StringIO()):
            CSV_TO_JSON.convert_all(directory, output, force)
        return {direction: json.loads((output / f"{direction}.json").read_text(encoding="utf-8"))
                for direction in ("ingress", "egress")}

    def write_tables(self, tables=None):
        directory = self.work / "input-csv"
        directory.mkdir(exist_ok=True)
        for protocol, fields in CSV_TO_JSON.CSV_FIELDS.items():
            with (directory / f"{protocol}.csv").open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows((tables or {}).get(protocol, []))
        return directory

    def row(self, protocol):
        row = {"direction": "ingress", "cidr": "192.0.2.0/24", "stateless": "false",
               "description": ""}
        if protocol in ("tcp", "udp"):
            row.update(dst_min="all", dst_max="all")
        elif protocol == "icmp":
            row.update(type="", code="")
        return row

    def assert_no_temporary_files(self, directory):
        if directory.exists():
            self.assertEqual(list(directory.glob("*.tmp")), [])

    def rich_rules(self):
        rules = {}
        description = '  日本語の説明, "引用符"\n2行目\r\n3行目\r4行目  '
        for direction in ("ingress", "egress"):
            rules[direction] = [
                make_rule(direction, "6", description=description, isStateless=True,
                          tcpOptions={"destinationPortRange": {"min": 1, "max": 65535}}),
                make_rule(direction, "6"),
                make_rule(direction, "17", description="UDPの説明",
                          udpOptions={"destinationPortRange": {"min": 53, "max": 53}}),
                make_rule(direction, "17", isStateless=True),
                make_rule(direction, "1", icmpOptions={"type": 3, "code": 4}),
                make_rule(direction, "1", icmpOptions={"type": 8}, description="コード未指定"),
                make_rule(direction, "1", description="全ICMP"),
                make_rule(direction, "all", description="全プロトコル"),
                make_rule(direction, "all", **{
                    "source" if direction == "ingress" else "destination": "2001:db8::/32"
                }),
            ]
        return rules

    def test_arrays_round_trip_all_protocols_directions_and_descriptions(self):
        rules = self.rich_rules()
        directory = self.export(rules["ingress"], rules["egress"])
        self.assertEqual(self.import_csv(directory), rules)
        for path in directory.glob("*.csv"):
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_cli_get_with_data_and_hyphenated_keys_round_trip(self):
        rules = self.rich_rules()
        get = self.write_json("get.json", {"data": hyphen_keys({
            "displayName": "Documentation example", "id": "sample-security-list",
            "ingressSecurityRules": rules["ingress"], "egressSecurityRules": rules["egress"]
        })})
        self.assertEqual(self.import_csv(self.export(get=get)), rules)

    def test_bare_get_object_with_camel_case_keys(self):
        rules = self.rich_rules()
        get = self.write_json("get.json", {"ingressSecurityRules": rules["ingress"],
                                           "egressSecurityRules": rules["egress"]})
        self.assertEqual(self.import_csv(self.export(get=get)), rules)

    def test_empty_rules_write_four_headers_and_two_empty_arrays(self):
        directory = self.export()
        for protocol, fields in CSV_TO_JSON.CSV_FIELDS.items():
            with (directory / f"{protocol}.csv").open(encoding="utf-8-sig", newline="") as stream:
                self.assertEqual(list(csv.reader(stream)), [fields])
        self.assertEqual(self.import_csv(directory), {"ingress": [], "egress": []})

    def test_null_optional_values_and_integer_protocol(self):
        rule = {"protocol": 1, "source": "192.0.2.0/24", "source-type": None,
                "is-stateless": None, "description": None, "icmp-options": None,
                "tcp-options": None, "udp-options": None}
        output = self.import_csv(self.export([rule]))["ingress"]
        self.assertEqual(output, [make_rule("ingress", "1")])

    def test_csv_normalizes_non_description_fields_and_preserves_description(self):
        row = self.row("tcp")
        row.update(direction="  EGRESS ", stateless=" TRUE ", dst_min=" ALL ", dst_max=" All ",
                   cidr=" 2001:db8::/32 ", description="  前後の空白を保存  ")
        actual = self.import_csv(self.write_tables({"tcp": [row]}))["egress"]
        self.assertEqual(actual, [make_rule("egress", "6", destination="2001:db8::/32",
                                           isStateless=True, description="  前後の空白を保存  ")])

    def test_csv_header_column_order_is_flexible(self):
        directory = self.write_tables()
        fields = list(reversed(CSV_TO_JSON.CSV_FIELDS["all"]))
        with (directory / "all.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerow(self.row("all"))
        self.assertEqual(self.import_csv(directory)["ingress"], [make_rule("ingress", "all")])

    def test_icmp_boundaries_type_only_and_all(self):
        for icmp_type, code, expected in [
            ("", "", None), ("0", "0", {"type": 0, "code": 0}),
            ("255", "255", {"type": 255, "code": 255}), ("8", "", {"type": 8})
        ]:
            with self.subTest(type=icmp_type, code=code):
                row = self.row("icmp")
                row.update(type=icmp_type, code=code)
                _, rule = CSV_TO_JSON.convert_rule(row, "icmp")
                self.assertEqual(rule.get("icmpOptions"), expected)
                _, exported = JSON_TO_CSV.convert_rule(rule, "ingress", 1)
                self.assertEqual(str(exported["type"]), icmp_type)
                self.assertEqual(str(exported["code"]), code)

    def test_csv_invalid_rule_values_are_rejected(self):
        cases = [
            ("all", "direction", "inbound"), ("all", "stateless", "yes"),
            ("all", "cidr", "192.0.2.5/24"), ("all", "cidr", "2001:db8::1/32"),
            ("all", "cidr", "invalid-cidr"), ("icmp", "cidr", "2001:db8::/32"),
            ("tcp", "dst_min", "0"), ("tcp", "dst_min", "-1"),
            ("tcp", "dst_min", "+1"), ("tcp", "dst_min", "1_0"),
            ("tcp", "dst_min", "１"), ("tcp", "dst_min", "1.0"),
            ("tcp", "dst_max", "65536"), ("udp", "dst_min", "53"),
            ("icmp", "code", "0"), ("icmp", "type", "256"),
            ("icmp", "type", "-1"), ("icmp", "type", "true"),
        ]
        for protocol, field, value in cases:
            with self.subTest(protocol=protocol, field=field, value=value):
                row = self.row(protocol)
                row[field] = value
                with self.assertRaises(ValueError):
                    CSV_TO_JSON.convert_rule(row, protocol)
        for protocol in ("tcp", "udp"):
            row = self.row(protocol)
            row.update(dst_min="100", dst_max="10")
            with self.assertRaises(ValueError):
                CSV_TO_JSON.convert_rule(row, protocol)

    def test_csv_bad_header_columns_encoding_and_quotes_rejected_before_output(self):
        cases = [
            b"", b"direction,cidr,stateless\ningress,192.0.2.0/24,false\n",
            b"direction,cidr,stateless,description,extra\n",
            b"direction,cidr,stateless,description,description\n",
            b"direction,cidr,stateless,description\ningress,192.0.2.0/24,false\n",
            b"direction,cidr,stateless,description\ningress,192.0.2.0/24,false,x,y\n",
            b'direction,cidr,stateless,description\ningress,192.0.2.0/24,false,"unterminated\n',
            b"direction,cidr,stateless,description\ningress,192.0.2.0/24,false,\xff\n",
        ]
        for content in cases:
            with self.subTest(content=content):
                directory = self.write_tables()
                (directory / "all.csv").write_bytes(content)
                with self.assertRaises((ValueError, csv.Error)):
                    self.import_csv(directory)
                self.assertFalse((self.work / "json").exists())

    def test_missing_csv_input_rejected_before_output(self):
        directory = self.write_tables()
        (directory / "all.csv").unlink()
        with self.assertRaises(ValueError):
            self.import_csv(directory)
        self.assertFalse((self.work / "json").exists())

    def test_invalid_json_rules_are_rejected(self):
        patches = [
            {"protocol": True}, {"protocol": None}, {"protocol": "58"},
            {"protocol": "132"}, {"protocol": 6.0}, {"sourceType": "SERVICE_CIDR_BLOCK"},
            {"sourceType": ""}, {"sourceType": False}, {"source": "192.0.2.5/24"},
            {"source": "2001:db8::1/32"}, {"source": 1}, {"source": "bad"},
            {"isStateless": "true"}, {"isStateless": 1}, {"description": 123},
            {"unexpected": "value"}, {"destination": "192.0.2.0/24"},
            {"udpOptions": {"destinationPortRange": {"min": 53, "max": 53}}},
            {"tcpOptions": {"sourcePortRange": {"min": 1, "max": 1}}},
            {"tcpOptions": {"unknown": None}}, {"tcpOptions": []},
            {"tcpOptions": {"destinationPortRange": []}},
            {"tcpOptions": {"destinationPortRange": {"min": 1}}},
            {"tcpOptions": {"destinationPortRange": {"min": 1, "max": 2, "extra": 0}}},
            {"tcpOptions": {"destinationPortRange": {"min": 2, "max": 1}}},
        ]
        for patch in patches:
            with self.subTest(patch=patch):
                with self.assertRaises(ValueError):
                    JSON_TO_CSV.convert_rule(make_rule("ingress", "6", **patch), "ingress", 1)
        for raw in (None, True, [], "rule"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    JSON_TO_CSV.convert_rule(raw, "ingress", 1)

    def test_json_port_integers_and_range_bounds_are_strict(self):
        for protocol, option in (("6", "tcpOptions"), ("17", "udpOptions")):
            for value in (True, False, 1.0, "1", None, -1, 0, 65536):
                for endpoint in ("min", "max"):
                    with self.subTest(protocol=protocol, value=value, endpoint=endpoint):
                        port_range = {"min": 1, "max": 65535}
                        port_range[endpoint] = value
                        rule = make_rule("ingress", protocol, **{
                            option: {"destinationPortRange": port_range}
                        })
                        with self.assertRaises(ValueError):
                            JSON_TO_CSV.convert_rule(rule, "ingress", 1)

    def test_json_invalid_icmp_options_are_rejected(self):
        cases = [{}, [], {"code": 0}, {"type": None}, {"type": True}, {"type": 8.0},
                 {"type": "8"}, {"type": -1}, {"type": 256}, {"type": 8, "code": True},
                 {"type": 8, "code": 1.0}, {"type": 8, "code": "0"},
                 {"type": 8, "code": 256}, {"type": 8, "unknown": None}]
        for options in cases:
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    JSON_TO_CSV.convert_rule(make_rule("ingress", "1", icmpOptions=options),
                                             "ingress", 1)
        with self.assertRaises(ValueError):
            JSON_TO_CSV.convert_rule(make_rule("ingress", "1", source="2001:db8::/32"),
                                     "ingress", 1)

    def test_raw_duplicate_and_normalized_duplicate_json_keys_are_rejected(self):
        duplicate_documents = [
            '[{"protocol":"6","protocol":"17"}]',
            '[{"tcpOptions":{"destinationPortRange":{"min":1,"min":2,"max":3}}}]',
            '{"data":{"ingress-security-rules":[],"ingress-security-rules":[],"egress-security-rules":[]}}',
        ]
        for content in duplicate_documents:
            with self.subTest(content=content):
                path = self.work / "duplicates.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "重複"):
                    JSON_TO_CSV.load_json(path)
        rule = make_rule("ingress", "6", **{"is-stateless": True})
        with self.assertRaisesRegex(ValueError, "重複"):
            JSON_TO_CSV.convert_rule(rule, "ingress", 1)

    def test_json_bad_encoding_syntax_and_nonstandard_constants(self):
        for content in (b"\xff", b"[{]", b"[NaN]", b"[Infinity]", b"[-Infinity]"):
            with self.subTest(content=content):
                path = self.work / "bad.json"
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    JSON_TO_CSV.load_json(path)

    def test_json_input_modes_and_shapes_are_checked(self):
        path = self.write_json("input.json", [])
        for args in [
            argparse.Namespace(oci_get=None, ingress=None, egress=None),
            argparse.Namespace(oci_get=None, ingress=path, egress=None),
            argparse.Namespace(oci_get=path, ingress=path, egress=None),
            argparse.Namespace(oci_get=path, ingress=None, egress=None),
        ]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    JSON_TO_CSV.read_inputs(args)
        for document in ({}, {"data": []}, {"ingress-security-rules": [],
                                              "egress-security-rules": {}},
                         {"data": {"ingress-security-rules": [], "ingressSecurityRules": [],
                                   "egress-security-rules": []}}):
            with self.subTest(document=document):
                path = self.write_json("bad-get.json", document)
                with self.assertRaises(ValueError):
                    JSON_TO_CSV.read_inputs(argparse.Namespace(oci_get=path, ingress=None, egress=None))
        with self.assertRaises(ValueError):
            JSON_TO_CSV.read_inputs(argparse.Namespace(
                oci_get=None, ingress=self.write_json("not-array.json", {}),
                egress=self.write_json("array.json", [])))

    def test_late_invalid_rule_does_not_write_or_modify_csv_outputs(self):
        output = self.export()
        before = {path.name: path.read_bytes() for path in output.iterdir()}
        rules = [make_rule("egress", "6"), make_rule("egress", "58")]
        with self.assertRaises(ValueError):
            self.export([make_rule("ingress", "6")], rules, output=output, force=True)
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)

    def test_late_invalid_csv_does_not_modify_json_outputs(self):
        directory = self.write_tables()
        self.import_csv(directory)
        output = self.work / "json"
        before = {path.name: path.read_bytes() for path in output.iterdir()}
        row = self.row("all")
        row["cidr"] = "192.0.2.1/24"
        directory = self.write_tables({"all": [row]})
        with self.assertRaises(ValueError):
            self.import_csv(directory, output=output, force=True)
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)

    def test_csv_output_overwrite_requires_force_and_rewrites_all_outputs(self):
        directory = self.export()
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        with self.assertRaises(ValueError):
            self.export([make_rule("ingress", "6")], output=directory)
        self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
        self.export([make_rule("ingress", "6")], output=directory, force=True)
        self.assertEqual(self.import_csv(directory)["ingress"], [make_rule("ingress", "6")])

    def test_json_output_overwrite_requires_force_even_when_only_egress_exists(self):
        directory = self.write_tables()
        output = self.work / "json"
        output.mkdir()
        (output / "egress.json").write_text("sentinel", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.import_csv(directory)
        self.assertFalse((output / "ingress.json").exists())
        self.assertEqual((output / "egress.json").read_text(), "sentinel")
        self.assertEqual(self.import_csv(directory, force=True), {"ingress": [], "egress": []})

    def test_output_destination_must_be_a_directory(self):
        output = self.work / "file"
        output.write_text("sentinel", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.export(output=output)
        with self.assertRaises(ValueError):
            self.import_csv(self.write_tables(), output=output)
        self.assertEqual(output.read_text(), "sentinel")

    def test_json_staging_write_failure_preserves_existing_outputs_and_cleans_temps(self):
        directory = self.write_tables()
        self.import_csv(directory)
        output = self.work / "json"
        before = {path.name: path.read_bytes() for path in output.iterdir()}
        original = CSV_TO_JSON.json.dump
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated staging failure")
            return original(*args, **kwargs)

        with mock.patch.object(CSV_TO_JSON.json, "dump", side_effect=fail_second):
            with self.assertRaises(OSError):
                self.import_csv(directory, force=True)
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)
        self.assert_no_temporary_files(output)

    def test_csv_staging_encoding_failure_preserves_all_existing_outputs_and_cleans_temps(self):
        output = self.export()
        before = {path.name: path.read_bytes() for path in output.iterdir()}
        with self.assertRaises(UnicodeError):
            self.export([make_rule("ingress", "6"),
                         make_rule("ingress", "all", description="\ud800")],
                        output=output, force=True)
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)
        self.assert_no_temporary_files(output)

    def test_destination_created_during_staging_is_not_overwritten(self):
        operation = "rename" if JSON_TO_CSV.os.name == "nt" else "link"
        original = getattr(JSON_TO_CSV.os, operation)
        output = self.work / "csv"

        def create_before_publish(source, destination):
            destination.write_text("sentinel", encoding="utf-8")
            return original(source, destination)

        with mock.patch.object(JSON_TO_CSV.os, operation, side_effect=create_before_publish):
            with self.assertRaises(FileExistsError):
                self.export(output=output)
        self.assertEqual((output / "tcp.csv").read_text(), "sentinel")
        self.assertEqual(sorted(path.name for path in output.iterdir()), ["tcp.csv"])

    def test_cli_success_and_invalid_utf8_return_codes(self):
        directory = self.write_tables({"icmp": [self.row("icmp")]})
        completed = subprocess.run(
            [sys.executable, str(ROOT / "oci_security_list_csv_to_json.py"),
             "--input-dir", str(directory), "--output-dir", str(self.work / "cli-json")],
            capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = subprocess.run(
            [sys.executable, str(ROOT / "oci_security_list_json_to_csv.py"),
             "--ingress", str(self.work / "cli-json/ingress.json"),
             "--egress", str(self.work / "cli-json/egress.json"),
             "--output-dir", str(self.work / "cli-csv")], capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        (directory / "all.csv").write_bytes(b"\xff")
        completed = subprocess.run(
            [sys.executable, str(ROOT / "oci_security_list_csv_to_json.py"),
             "--input-dir", str(directory), "--output-dir", str(self.work / "bad-output")],
            capture_output=True)
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn(b"Traceback", completed.stderr)
        self.assertFalse((self.work / "bad-output").exists())


if __name__ == "__main__":
    unittest.main()

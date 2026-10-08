"""Round-trip and fail-closed tests with documentation CIDRs and synthetic service labels."""

import argparse
import base64
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


def make_service_rule(direction, protocol_code, label="oci-example-objectstorage", **extra):
    """Use an opaque, synthetic service label rather than a real environment export."""
    address = "source" if direction == "ingress" else "destination"
    address_type = "sourceType" if direction == "ingress" else "destinationType"
    rule = make_rule(direction, protocol_code, **{
        address: label, address_type: "SERVICE_CIDR_BLOCK"
    })
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
            self.last_unconverted = JSON_TO_CSV.export_csv(args)
        return args.output_dir

    def import_csv(self, directory, output=None, force=False):
        output = output or self.work / "json"
        with contextlib.redirect_stdout(io.StringIO()):
            CSV_TO_JSON.convert_all(directory, output, force)
        return {direction: json.loads((output / f"{direction}.json").read_text(encoding="utf-8"))
                for direction in ("ingress", "egress")}

    def write_tables(self, tables=None, legacy=False):
        directory = self.work / "input-csv"
        directory.mkdir(exist_ok=True)
        for protocol in ("tcp", "udp", "icmp", "all"):
            fields = CSV_TO_JSON.CSV_FIELDS[protocol]
            if legacy:
                fields = [field for field in fields if field != "address_type"]
            with (directory / f"{protocol}.csv").open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                for row in (tables or {}).get(protocol, []):
                    if legacy:
                        row = {key: value for key, value in row.items() if key != "address_type"}
                    writer.writerow(row)
        if tables and "service" in tables:
            with (directory / "service.csv").open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "direction", "cidr", "protocol", "dst_min", "dst_max", "type", "code",
                    "stateless", "description"])
                writer.writeheader()
                writer.writerows(tables["service"])
        return directory

    def read_table(self, directory, name):
        with (directory / f"{name}.csv").open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    def read_report(self, directory):
        return json.loads((directory / "unconverted-rules.json").read_text(encoding="utf-8"))

    def assert_complete_report(self, directory):
        report = self.read_report(directory)
        self.assertEqual(report["format_version"], 1)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["ingress"], [])
        self.assertEqual(report["egress"], [])
        self.assertEqual(self.last_unconverted, 0)

    def service_row(self, protocol, direction="ingress", **changes):
        row = {"direction": direction, "cidr": "oci-example-objectstorage", "protocol": protocol,
               "dst_min": "", "dst_max": "", "type": "", "code": "",
               "stateless": "false", "description": ""}
        if protocol in ("tcp", "udp"):
            row.update(dst_min="all", dst_max="all")
        row.update(changes)
        return row

    def run_json_cli(self, arguments, output=None, force=False):
        output = output or self.work / "cli-csv"
        command = [sys.executable, str(ROOT / "oci_security_list_json_to_csv.py"),
                   "--output-dir", str(output)] + arguments
        if force:
            command.append("--force")
        return subprocess.run(command, cwd=self.work, capture_output=True), output

    def row(self, protocol):
        row = {"direction": "ingress", "cidr": "192.0.2.0/24", "address_type": "CIDR_BLOCK",
               "stateless": "false",
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

    def service_rules(self):
        rules = {}
        description = '  日本語のサービス説明, "引用符"\n2行目\r\n3行目  '
        for direction in ("ingress", "egress"):
            rules[direction] = [
                make_service_rule(direction, "6", description=description, isStateless=True,
                                  tcpOptions={"destinationPortRange": {"min": 443, "max": 443}}),
                make_service_rule(direction, "17", description=description,
                                  udpOptions={"destinationPortRange": {"min": 5000, "max": 5010}}),
                make_service_rule(direction, "1", description=description,
                                  icmpOptions={"type": 3, "code": 4}),
                make_service_rule(direction, "all", description=description, isStateless=True),
            ]
        return rules

    def test_csv_export_schema_includes_explicit_address_type(self):
        expected_fields = {
            "tcp": ["direction", "cidr", "address_type", "dst_min", "dst_max", "stateless", "description"],
            "udp": ["direction", "cidr", "address_type", "dst_min", "dst_max", "stateless", "description"],
            "icmp": ["direction", "cidr", "address_type", "type", "code", "stateless", "description"],
            "all": ["direction", "cidr", "address_type", "stateless", "description"],
            "service": ["direction", "cidr", "protocol", "dst_min", "dst_max", "type", "code",
                        "stateless", "description"],
        }
        directory = self.export()
        for protocol, fields in expected_fields.items():
            with self.subTest(protocol=protocol):
                with (directory / f"{protocol}.csv").open(encoding="utf-8-sig", newline="") as stream:
                    self.assertEqual(list(csv.reader(stream)), [fields])
        self.assert_complete_report(directory)

    def test_service_arrays_round_trip_all_protocols_directions_and_descriptions(self):
        rules = self.service_rules()
        directory = self.export(rules["ingress"], rules["egress"])
        for protocol in ("tcp", "udp", "icmp", "all"):
            self.assertEqual(self.read_table(directory, protocol), [])
        rows = self.read_table(directory, "service")
        self.assertEqual(len(rows), 8)
        self.assertEqual([row["direction"] for row in rows], ["ingress"] * 4 + ["egress"] * 4)
        self.assertEqual([row["protocol"] for row in rows], ["tcp", "udp", "icmp", "all"] * 2)
        self.assertEqual([row["cidr"] for row in rows], ["oci-example-objectstorage"] * 8)
        self.assertNotIn("address_type", rows[0])
        self.assertEqual((rows[0]["dst_min"], rows[0]["dst_max"], rows[0]["type"], rows[0]["code"]),
                         ("443", "443", "", ""))
        self.assertEqual((rows[2]["dst_min"], rows[2]["dst_max"], rows[2]["type"], rows[2]["code"]),
                         ("", "", "3", "4"))
        self.assert_complete_report(directory)
        self.assertEqual(self.import_csv(directory), rules)

    def test_mixed_service_and_ip_cidrs_round_trip_cli_get_hyphenated_keys(self):
        service_rules = self.service_rules()
        rules = {}
        for direction in ("ingress", "egress"):
            rules[direction] = []
            for service_rule in service_rules[direction]:
                rules[direction].extend([
                    make_rule(direction, service_rule["protocol"], description="文書用IP CIDR"),
                    service_rule,
                ])
        get = self.write_json("service-get.json", {"data": hyphen_keys({
            "displayName": "Synthetic service example", "id": "synthetic-resource",
            "ingressSecurityRules": rules["ingress"], "egressSecurityRules": rules["egress"]
        }), "etag": "synthetic-etag"})
        directory = self.export(get=get)
        for protocol in ("tcp", "udp", "icmp", "all"):
            with self.subTest(protocol=protocol):
                with (directory / f"{protocol}.csv").open(encoding="utf-8-sig", newline="") as stream:
                    rows = list(csv.DictReader(stream))
                self.assertEqual([row["address_type"] for row in rows], ["CIDR_BLOCK"] * 2)
                self.assertNotIn("id", rows[0])
        service_rows = self.read_table(directory, "service")
        self.assertEqual(len(service_rows), 8)
        self.assertEqual(sum(len(self.read_table(directory, name))
                             for name in ("tcp", "udp", "icmp", "all", "service")), 16)
        self.assert_complete_report(directory)
        self.assertEqual(self.import_csv(directory), rules)

    def test_csv_service_labels_and_descriptions_are_preserved_as_opaque_text(self):
        label = '  synthetic label, "quoted"\nsecond line  '
        description = ' =1+1, "説明の引用符"\r\n空白を保持  '
        tables = {}
        expected = {"ingress": [], "egress": []}
        for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
            tables[protocol] = []
            for direction in ("ingress", "egress"):
                row = self.row(protocol)
                row.update(direction=direction, cidr=label, address_type=" SERVICE_CIDR_BLOCK ",
                           description=description)
                tables[protocol].append(row)
                expected[direction].append(make_service_rule(direction, code, label,
                                                               description=description))
        converted = self.import_csv(self.write_tables(tables))
        self.assertEqual(converted, expected)
        self.assertEqual(self.import_csv(self.export(converted["ingress"], converted["egress"]),
                                         output=self.work / "roundtrip-json"), expected)

    def test_legacy_csv_without_address_type_defaults_to_cidr_for_all_protocols(self):
        tables = {}
        expected = {"ingress": [], "egress": []}
        for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
            tables[protocol] = []
            for direction in ("ingress", "egress"):
                row = self.row(protocol)
                row.update(direction=direction, description="旧CSV互換")
                tables[protocol].append(row)
                expected[direction].append(make_rule(direction, code, description="旧CSV互換"))
        self.assertEqual(self.import_csv(self.write_tables(tables, legacy=True)), expected)

    def test_blank_csv_address_type_defaults_to_cidr(self):
        for address_type in ("", " \t "):
            with self.subTest(address_type=address_type):
                tables = {}
                expected = {"ingress": [], "egress": []}
                for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
                    tables[protocol] = []
                    for direction in ("ingress", "egress"):
                        row = self.row(protocol)
                        row.update(direction=direction, address_type=address_type)
                        tables[protocol].append(row)
                        expected[direction].append(make_rule(direction, code))
                self.assertEqual(self.import_csv(self.write_tables(tables), force=True), expected)

    def test_csv_cidr_address_type_allows_surrounding_whitespace(self):
        for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
            with self.subTest(protocol=protocol):
                row = self.row(protocol)
                row["address_type"] = " \tCIDR_BLOCK\t "
                self.assertEqual(CSV_TO_JSON.convert_rule(row, protocol),
                                 ("ingress", make_rule("ingress", code)))

    def test_csv_unknown_address_types_are_rejected_before_output(self):
        for address_type in ("UNKNOWN", "NETWORK_SECURITY_GROUP", "cidr_block", "service_cidr_block"):
            for protocol in ("tcp", "udp", "icmp", "all"):
                for direction in ("ingress", "egress"):
                    with self.subTest(address_type=address_type, protocol=protocol, direction=direction):
                        row = self.row(protocol)
                        row.update(direction=direction, address_type=address_type)
                        with self.assertRaises(ValueError):
                            self.import_csv(self.write_tables({protocol: [row]}))
                        self.assertFalse((self.work / "json").exists())

    def test_json_unknown_address_types_are_saved_as_partial_without_stopping_export(self):
        for address_type in ("", " ", "UNKNOWN", "NETWORK_SECURITY_GROUP", "cidr_block",
                             "service_cidr_block", " CIDR_BLOCK ", False, 1):
            for direction in ("ingress", "egress"):
                with self.subTest(address_type=address_type, direction=direction):
                    type_key = "sourceType" if direction == "ingress" else "destinationType"
                    rule = make_rule(direction, "all", **{type_key: address_type})
                    output = self.export(force=True, **{direction: [rule]})
                    self.assertEqual(self.last_unconverted, 1)
                    report = self.read_report(output)
                    self.assertEqual(report["status"], "partial")
                    self.assertEqual(report[direction][0]["rule"], rule)
                    self.assertEqual(report[direction][0]["index"], 1)
                    self.assertTrue(report[direction][0]["error"])
                    self.assertEqual(report["egress" if direction == "ingress" else "ingress"], [])

    def test_empty_service_labels_are_rejected_in_both_directions_and_formats(self):
        for label in ("", " ", "\t\r\n"):
            for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
                for direction in ("ingress", "egress"):
                    with self.subTest(label=label, protocol=protocol, direction=direction):
                        row = self.row(protocol)
                        row.update(direction=direction, cidr=label, address_type="SERVICE_CIDR_BLOCK")
                        with self.assertRaises(ValueError):
                            CSV_TO_JSON.convert_rule(row, protocol)
                        with self.assertRaises(ValueError):
                            JSON_TO_CSV.convert_rule(make_service_rule(direction, code, label), direction, 1)
        for label in (None, 1, True, [], {}):
            for direction in ("ingress", "egress"):
                with self.subTest(label=label, direction=direction):
                    with self.assertRaises(ValueError):
                        JSON_TO_CSV.convert_rule(make_service_rule(direction, "all", label), direction, 1)

    def test_service_label_is_not_inferred_from_missing_or_blank_address_type(self):
        for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
            for direction in ("ingress", "egress"):
                for address_type in (None, "", " "):
                    with self.subTest(protocol=protocol, direction=direction, address_type=address_type):
                        row = self.row(protocol)
                        row.update(direction=direction, cidr="oci-example-objectstorage")
                        if address_type is None:
                            row.pop("address_type")
                        else:
                            row["address_type"] = address_type
                        with self.assertRaises(ValueError):
                            CSV_TO_JSON.convert_rule(row, protocol)
                for missing in (True, False):
                    with self.subTest(protocol=protocol, direction=direction, missing=missing):
                        rule = make_service_rule(direction, code)
                        type_key = "sourceType" if direction == "ingress" else "destinationType"
                        if missing:
                            rule.pop(type_key)
                        else:
                            rule[type_key] = None
                        with self.assertRaises(ValueError):
                            JSON_TO_CSV.convert_rule(rule, direction, 1)

    def test_invalid_service_labels_make_json_export_partial_and_csv_import_fail_closed(self):
        output_csv = self.export()
        invalid_rule = make_service_rule("egress", "all", " ")
        self.export([make_rule("ingress", "6")], [invalid_rule], output=output_csv, force=True)
        self.assertEqual(self.last_unconverted, 1)
        self.assertEqual(len(self.read_table(output_csv, "tcp")), 1)
        self.assertEqual(self.read_report(output_csv)["egress"][0]["rule"], invalid_rule)
        with self.assertRaises(ValueError):
            self.import_csv(output_csv)
        self.assertFalse((self.work / "json").exists())
        directory = self.write_tables()
        output_json = self.work / "json"
        self.import_csv(directory)
        before_json = {path.name: path.read_bytes() for path in output_json.iterdir()}
        invalid = self.row("all")
        invalid.update(direction="egress", cidr=" ", address_type="SERVICE_CIDR_BLOCK")
        directory = self.write_tables({"tcp": [self.row("tcp")], "all": [invalid]})
        with self.assertRaises(ValueError):
            self.import_csv(directory, output=output_json, force=True)
        self.assertEqual({path.name: path.read_bytes() for path in output_json.iterdir()}, before_json)

    def test_empty_rules_write_five_headers_complete_report_and_two_empty_arrays(self):
        directory = self.export()
        for protocol, fields in JSON_TO_CSV.CSV_FIELDS.items():
            with (directory / f"{protocol}.csv").open(encoding="utf-8-sig", newline="") as stream:
                self.assertEqual(list(csv.reader(stream)), [fields])
        self.assert_complete_report(directory)
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
            {"protocol": "132"}, {"protocol": 6.0}, {"sourceType": "UNKNOWN"},
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

    def test_late_invalid_rule_is_reported_while_supported_rules_are_exported(self):
        invalid = make_rule("egress", "58")
        rules = [make_rule("egress", "6"), invalid, make_rule("egress", "17")]
        output = self.export([make_rule("ingress", "6")], rules)
        self.assertEqual(self.last_unconverted, 1)
        self.assertEqual(len(self.read_table(output, "tcp")), 2)
        self.assertEqual(len(self.read_table(output, "udp")), 1)
        report = self.read_report(output)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["egress"][0]["index"], 2)
        self.assertEqual(report["egress"][0]["rule"], invalid)
        self.assertTrue(report["egress"][0]["error"])
        with self.assertRaises(ValueError):
            self.import_csv(output)
        self.assertFalse((self.work / "json").exists())

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

    def test_csv_staging_write_failure_preserves_all_existing_outputs_and_cleans_temps(self):
        output = self.export()
        before = {path.name: path.read_bytes() for path in output.iterdir()}
        original = JSON_TO_CSV.csv.DictWriter.writerows
        calls = 0

        def fail_second(writer, rows):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated CSV staging failure")
            return original(writer, rows)

        with mock.patch.object(JSON_TO_CSV.csv.DictWriter, "writerows", new=fail_second):
            with self.assertRaises(OSError):
                self.export([make_rule("ingress", "6")], output=output, force=True)
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

    def test_dedicated_service_csv_imports_all_protocols_without_duplicating_legacy_services(self):
        tables = {"service": []}
        expected = {"ingress": [], "egress": []}
        for protocol, code in (("tcp", "6"), ("udp", "17"), ("icmp", "1"), ("all", "all")):
            for direction in ("ingress", "egress"):
                tables["service"].append(self.service_row(protocol, direction))
                expected[direction].append(make_service_rule(direction, code))
        self.assertEqual(self.import_csv(self.write_tables(tables)), expected)
        legacy = self.row("tcp")
        legacy.update(cidr="oci-legacy-example", address_type="SERVICE_CIDR_BLOCK")
        directory = self.write_tables({"tcp": [legacy], "service": [self.service_row("tcp")]})
        actual = self.import_csv(directory, output=self.work / "mixed-json")
        self.assertEqual(actual["ingress"], [make_service_rule("ingress", "6", "oci-legacy-example"),
                                             make_service_rule("ingress", "6")])

    def test_service_csv_unused_columns_and_unknown_protocol_are_rejected_before_output(self):
        cases = [("tcp", "type", "3"), ("tcp", "code", "4"),
                 ("udp", "type", "8"), ("udp", "code", "0"),
                 ("icmp", "dst_min", "all"), ("icmp", "dst_max", "443"),
                 ("all", "dst_min", "all"), ("all", "dst_max", "all"),
                 ("all", "type", "3"), ("all", "code", "4")]
        for protocol, field, value in cases:
            with self.subTest(protocol=protocol, field=field):
                row = self.service_row(protocol, **{field: value})
                with self.assertRaises(ValueError):
                    self.import_csv(self.write_tables({"service": [row]}))
                self.assertFalse((self.work / "json").exists())
        for protocol in ("", "58", "6", "unknown"):
            with self.subTest(protocol=protocol):
                with self.assertRaises(ValueError):
                    self.import_csv(self.write_tables({"service": [self.service_row(protocol)]}))
                self.assertFalse((self.work / "json").exists())

    def test_import_sorts_protocols_stably_after_separate_service_file(self):
        tables = {"tcp": [self.row("tcp")], "all": [self.row("all")], "service": [
            self.service_row("all", description="service all first"),
            self.service_row("tcp", description="service tcp first"),
            self.service_row("icmp"),
            self.service_row("tcp", description="service tcp second"),
        ]}
        actual = self.import_csv(self.write_tables(tables))["ingress"]
        self.assertEqual(actual, [make_rule("ingress", "6"),
                                 make_service_rule("ingress", "6", description="service tcp first"),
                                 make_service_rule("ingress", "6", description="service tcp second"),
                                 make_service_rule("ingress", "1"), make_rule("ingress", "all"),
                                 make_service_rule("ingress", "all", description="service all first")])

    def test_partial_get_report_preserves_original_hyphenated_rules_and_indices(self):
        invalid_ingress = hyphen_keys(make_service_rule("ingress", "6", tcpOptions={
            "sourcePortRange": {"min": 443, "max": 443}}, description='未変換, "原文"\n2行目'))
        invalid_egress = hyphen_keys(make_rule("egress", "58", description="ICMPv6未対応"))
        raw_ingress = [hyphen_keys(make_rule("ingress", "6")), invalid_ingress, None,
                       hyphen_keys(make_service_rule("ingress", "all"))]
        get = self.write_json("partial-get.json", {"data": {
            "ingress-security-rules": raw_ingress,
            "egress-security-rules": [invalid_egress, hyphen_keys(make_rule("egress", "17"))]}})
        output = self.export(get=get)
        self.assertEqual(self.last_unconverted, 3)
        report = self.read_report(output)
        self.assertEqual(report["format_version"], 1)
        self.assertEqual(report["status"], "partial")
        self.assertEqual([entry["index"] for entry in report["ingress"]], [2, 3])
        self.assertEqual([entry["rule"] for entry in report["ingress"]], [invalid_ingress, None])
        self.assertEqual(report["egress"][0]["rule"], invalid_egress)
        self.assertEqual(report["egress"][0]["index"], 1)
        self.assertTrue(all(entry["error"] for direction in ("ingress", "egress")
                            for entry in report[direction]))
        self.assertEqual(len(self.read_table(output, "tcp")), 1)
        self.assertEqual(len(self.read_table(output, "udp")), 1)
        self.assertEqual(len(self.read_table(output, "service")), 1)

    def test_surrogate_description_is_partial_and_saved_without_losing_supported_rows(self):
        bad = make_rule("ingress", "all", description="\ud800")
        output = self.export([make_rule("ingress", "6"), bad])
        self.assertEqual(self.last_unconverted, 1)
        self.assertEqual(self.read_report(output)["ingress"][0]["rule"], bad)
        self.assertEqual(len(self.read_table(output, "tcp")), 1)
        self.assertEqual(self.read_table(output, "all"), [])

    def test_force_complete_replaces_partial_report_and_removes_stale_service_rows(self):
        output = self.export([make_service_rule("ingress", "6"), make_rule("ingress", "58")])
        self.assertEqual(self.read_report(output)["status"], "partial")
        self.assertEqual(len(self.read_table(output, "service")), 1)
        self.export([make_rule("ingress", "17")], output=output, force=True)
        self.assert_complete_report(output)
        self.assertEqual(self.read_table(output, "service"), [])
        self.assertEqual(self.read_table(output, "tcp"), [])
        self.assertEqual(self.import_csv(output)["ingress"], [make_rule("ingress", "17")])

    def test_existing_report_alone_requires_force_and_is_not_overwritten(self):
        output = self.work / "csv"
        output.mkdir()
        report_path = output / "unconverted-rules.json"
        report_path.write_text("sentinel", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.export(output=output)
        self.assertEqual(report_path.read_text(), "sentinel")
        self.assertEqual(list(output.glob("*.csv")), [])
        self.export(output=output, force=True)
        self.assert_complete_report(output)

    def test_import_rejects_incomplete_failed_unknown_or_malformed_report_without_changing_json(self):
        directory = self.write_tables({"tcp": [self.row("tcp")]})
        self.import_csv(directory)
        output = self.work / "json"
        before = {path.name: path.read_bytes() for path in output.iterdir()}
        complete = {"format_version": 1, "status": "complete", "ingress": [], "egress": []}
        bad_reports = [[], {}, {**complete, "status": "partial"}, {**complete, "status": "failed"},
                       {**complete, "status": "unknown"}, {**complete, "format_version": 2},
                       {**complete, "format_version": True}, {**complete, "ingress": [None]},
                       {**complete, "egress": {}}, {key: value for key, value in complete.items()
                                                      if key != "status"}]
        report_path = directory / "unconverted-rules.json"
        for report in bad_reports:
            with self.subTest(report=report):
                report_path.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.import_csv(directory, output=output, force=True)
                self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)
        for raw in (b"{", b"\xff", b'{"format_version":1,"format_version":2}'):
            with self.subTest(raw=raw):
                report_path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.import_csv(directory, output=output, force=True)
                self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)
        report_path.write_text(json.dumps(complete), encoding="utf-8")
        self.assertEqual(self.import_csv(directory, output=output, force=True)["ingress"],
                         [make_rule("ingress", "6")])

    def test_fatal_cli_malformed_json_saves_input_text_and_does_not_create_csv(self):
        path = self.work / "broken-get.json"
        text = '{"data": {"description": "文書用の原文"\n'
        path.write_bytes(text.encode("utf-8"))
        completed, output = self.run_json_cli(["--oci-get", str(path)])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertNotIn(b"Traceback", completed.stderr)
        self.assertEqual(list(output.glob("*.csv")), [])
        report = self.read_report(output)
        self.assertEqual(report["format_version"], 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual((report["ingress"], report["egress"]), ([], []))
        self.assertTrue(report["error"])
        self.assertEqual(report["inputs"], [{"argument": "--oci-get", "file": path.name, "text": text}])

    def test_fatal_cli_invalid_utf8_saves_recoverable_base64(self):
        path = self.work / "non-utf8.json"
        raw = b'{"synthetic":"\xff\xfe"}'
        path.write_bytes(raw)
        completed, output = self.run_json_cli(["--oci-get", str(path)])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report = self.read_report(output)
        self.assertEqual(report["status"], "failed")
        saved = report["inputs"][0]
        self.assertEqual(saved["argument"], "--oci-get")
        self.assertEqual(saved["file"], path.name)
        self.assertEqual(base64.b64decode(saved["base64"], validate=True), raw)
        self.assertNotIn("text", saved)
        self.assertEqual(list(output.glob("*.csv")), [])

    def test_overflow_json_number_cannot_publish_invalid_json_report_or_partial_csv(self):
        ingress = self.work / "overflow-ingress.json"
        text = '[{"protocol":"6","source":"192.0.2.0/24"},' \
               '{"protocol":"58","source":"192.0.2.0/24","synthetic-number":1e309}]'
        ingress.write_bytes(text.encode("utf-8"))
        egress = self.write_json("overflow-egress.json", [])
        completed, output = self.run_json_cli(["--ingress", str(ingress), "--egress", str(egress)])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report_text = (output / "unconverted-rules.json").read_text(encoding="utf-8")
        self.assertNotIn("Infinity", report_text)
        report = self.read_report(output)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["inputs"][0]["text"], text)
        self.assertEqual(list(output.glob("*.csv")), [])
        self.assert_no_temporary_files(output)

    def test_fatal_cli_missing_file_records_read_error_and_original_filename(self):
        missing = self.work / "missing-input.json"
        completed, output = self.run_json_cli(["--oci-get", str(missing)])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report = self.read_report(output)
        self.assertEqual(report["status"], "failed")
        saved = report["inputs"][0]
        self.assertEqual(saved["file"], missing.name)
        self.assertTrue(saved["read_error"])
        self.assertNotIn("text", saved)
        self.assertEqual(list(output.glob("*.csv")), [])

    def test_fatal_cli_argument_error_writes_failed_report_without_a_traceback(self):
        completed, output = self.run_json_cli(["--unknown-test-option"])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertNotIn(b"Traceback", completed.stderr)
        report = self.read_report(output)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["error"])
        self.assertEqual(report["inputs"], [])
        self.assertEqual(list(output.glob("*.csv")), [])

    def test_normalized_duplicate_keys_in_one_get_rule_are_partial_and_raw_is_retained(self):
        bad = hyphen_keys(make_service_rule("ingress", "6"))
        bad["isStateless"] = True
        get = self.write_json("duplicate-rule-get.json", {"data": {
            "ingress-security-rules": [bad, hyphen_keys(make_rule("ingress", "17"))],
            "egress-security-rules": []}})
        output = self.export(get=get)
        self.assertEqual(self.last_unconverted, 1)
        report = self.read_report(output)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["ingress"][0]["rule"], bad)
        self.assertIn("重複", report["ingress"][0]["error"])
        self.assertEqual(len(self.read_table(output, "udp")), 1)

    def test_dedicated_service_csv_rejects_extra_address_type_header(self):
        directory = self.write_tables()
        row = self.service_row("tcp", address_type="CIDR_BLOCK")
        with (directory / "service.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(row))
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaises(ValueError):
            self.import_csv(directory)
        self.assertFalse((self.work / "json").exists())

    def test_fatal_cli_wrong_input_shape_saves_both_original_array_documents(self):
        ingress = self.write_json("wrong-shape.json", {"documentation": "not an array"})
        egress = self.write_json("valid-empty-array.json", [])
        completed, output = self.run_json_cli(["--ingress", str(ingress), "--egress", str(egress)])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report = self.read_report(output)
        self.assertEqual(report["status"], "failed")
        self.assertEqual([item["argument"] for item in report["inputs"]], ["--ingress", "--egress"])
        self.assertEqual([item["text"] for item in report["inputs"]],
                         [path.read_text(encoding="utf-8") for path in (ingress, egress)])
        self.assertEqual(list(output.glob("*.csv")), [])

    def test_partial_cli_returns_one_and_csv_import_cli_refuses_incomplete_subset(self):
        ingress = self.write_json("partial-ingress.json", [make_service_rule("ingress", "6"),
                                                          make_rule("ingress", "58")])
        egress = self.write_json("partial-egress.json", [make_rule("egress", "17")])
        completed, output = self.run_json_cli(["--ingress", str(ingress), "--egress", str(egress)])
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(self.read_report(output)["status"], "partial")
        self.assertEqual(len(self.read_table(output, "service")), 1)
        target = self.work / "guarded-json"
        result = subprocess.run([sys.executable, str(ROOT / "oci_security_list_csv_to_json.py"),
                                 "--input-dir", str(output), "--output-dir", str(target)], capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(target.exists())
        ingress.write_text("[]", encoding="utf-8")
        completed, output = self.run_json_cli(["--ingress", str(ingress), "--egress", str(egress)],
                                              output=output, force=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.read_report(output)["status"], "complete")
        self.assertEqual(self.read_table(output, "service"), [])

    def test_failed_report_after_force_protects_old_csv_from_import(self):
        output = self.export([make_rule("ingress", "6")])
        before = {path.name: path.read_bytes() for path in output.glob("*.csv")}
        bad = self.work / "failed-get.json"
        bad.write_text("{", encoding="utf-8")
        completed, output = self.run_json_cli(["--oci-get", str(bad)], output=output, force=True)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual({path.name: path.read_bytes() for path in output.glob("*.csv")}, before)
        self.assertEqual(self.read_report(output)["status"], "failed")
        with self.assertRaises(ValueError):
            self.import_csv(output)
        self.assertFalse((self.work / "json").exists())

    def test_public_examples_arrays_get_and_five_csvs_have_identical_rule_meanings(self):
        expected = {direction: json.loads((ROOT / "examples/json" / f"{direction}.json").read_text(encoding="utf-8-sig"))
                    for direction in ("ingress", "egress")}
        from_get = self.export(get=ROOT / "examples/oci-get.json")
        self.assert_complete_report(from_get)
        self.assertEqual(self.import_csv(from_get), expected)
        self.assertEqual(self.import_csv(ROOT / "examples/csv", output=self.work / "example-json"), expected)
        self.assertEqual(len(self.read_table(from_get, "service")), 2)
        self.assertEqual(sum(len(self.read_table(from_get, name))
                             for name in ("tcp", "udp", "icmp", "all", "service")), 12)


if __name__ == "__main__":
    unittest.main()

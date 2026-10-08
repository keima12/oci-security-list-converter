#!/usr/bin/env python3
"""OCI Security List JSON -> tcp/udp/icmp/all CSV converter.

Supports:
  - CLI rule arrays: --ingress ingress.json --egress egress.json
  - Original OCI CLI get output: --oci-get source.json

Requires Python 3.9+ and no external packages.
The output schema is compatible with the previously shown CSV -> JSON generator.
Unsupported OCI features fail explicitly to prevent silent rule loss.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path

CSV_FIELDS = {
    "tcp": ["direction", "cidr", "dst_min", "dst_max", "stateless", "description"],
    "udp": ["direction", "cidr", "dst_min", "dst_max", "stateless", "description"],
    "icmp": ["direction", "cidr", "type", "code", "stateless", "description"],
    "all": ["direction", "cidr", "stateless", "description"],
}
PROTOCOL_TO_CSV = {"6": "tcp", "17": "udp", "1": "icmp", "all": "all"}
COMMON_FIELDS = {
    "protocol", "isStateless", "description", "tcpOptions", "udpOptions", "icmpOptions"
}


def die(message):
    raise ValueError(message)


def load_json(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                die(f"JSONキーが重複しています: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        die(f"JSONの非標準数値は使用できません: {value}")

    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            return json.load(stream, object_pairs_hook=unique_object,
                             parse_constant=reject_constant)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path}: JSON読み込みに失敗しました: {exc}") from exc


def camel_key(key):
    return re.sub(r"-([a-z])", lambda match: match.group(1).upper(), key)


def normalize_keys(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = camel_key(key)
            if normalized in result:
                die(f"同じキーが重複しています: {key} / {normalized}")
            result[normalized] = normalize_keys(item)
        return result
    if isinstance(value, list):
        return [normalize_keys(item) for item in value]
    return value


def check_fields(obj, permitted, where):
    unexpected = set(obj) - permitted
    if unexpected:
        die(f"{where}: CSVに表現できない項目があります: {', '.join(sorted(unexpected))}")


def integer(value, label, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        die(f"{label}: {low}～{high}の整数が必要です（実際の値: {value!r}）")
    return value


def port_columns(rule, protocol, where):
    opt_name = "tcpOptions" if protocol == "tcp" else "udpOptions"
    options = rule.get(opt_name)
    if options is None:
        return "all", "all"
    if not isinstance(options, dict):
        die(f"{where}: {opt_name}はオブジェクトが必要です")
    check_fields(options, {"destinationPortRange", "sourcePortRange"}, where)
    if options.get("sourcePortRange") is not None:
        die(f"{where}: 送信元ポート制限（sourcePortRange）は現在のCSV形式で表現できません")
    pr = options.get("destinationPortRange")
    if pr is None:
        return "all", "all"
    if not isinstance(pr, dict):
        die(f"{where}: destinationPortRangeはオブジェクトが必要です")
    check_fields(pr, {"min", "max"}, where)
    if "min" not in pr or "max" not in pr:
        die(f"{where}: destinationPortRangeにはminとmaxが必要です")
    minimum = integer(pr["min"], f"{where}: min", 1, 65535)
    maximum = integer(pr["max"], f"{where}: max", 1, 65535)
    if minimum > maximum:
        die(f"{where}: ポート範囲 min > max")
    return minimum, maximum


def convert_rule(raw, direction, index):
    where = f"{direction}[{index}]"
    if not isinstance(raw, dict):
        die(f"{where}: ルールはJSONオブジェクトである必要があります")
    rule = normalize_keys(raw)
    addr_key = "source" if direction == "ingress" else "destination"
    type_key = "sourceType" if direction == "ingress" else "destinationType"
    check_fields(rule, COMMON_FIELDS | {addr_key, type_key}, where)

    proto_value = rule.get("protocol")
    if isinstance(proto_value, bool):
        die(f"{where}: 不正なprotocol値")
    protocol = str(proto_value)
    if protocol not in PROTOCOL_TO_CSV:
        die(f"{where}: 未対応のprotocol {proto_value!r}（6/17/1/allのみ）")
    name = PROTOCOL_TO_CSV[protocol]

    addr_type = rule.get(type_key)
    if addr_type is None:
        addr_type = "CIDR_BLOCK"
    if addr_type != "CIDR_BLOCK":
        die(f"{where}: {type_key}={addr_type!r}（サービスCIDR等）は未対応です")
    address = rule.get(addr_key)
    if not isinstance(address, str):
        die(f"{where}: {addr_key}はCIDR文字列が必要です")
    try:
        network = ipaddress.ip_network(address, strict=True)
    except ValueError as exc:
        raise ValueError(f"{where}: CIDRが不正です: {address!r}") from exc

    if name == "icmp" and network.version != 4:
        die(f"{where}: IPv6 ICMPは前回のCSV→JSONスクリプトで未対応です")

    stateless = rule.get("isStateless", False)
    if stateless is None:
        stateless = False
    if not isinstance(stateless, bool):
        die(f"{where}: isStatelessはtrue/falseで指定してください")

    description = rule.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        die(f"{where}: descriptionは文字列である必要があります")

    csv_row = {
        "direction": direction,
        "cidr": str(network),
        "stateless": str(stateless).lower(),
        "description": description,
    }

    for opt_key in ("tcpOptions", "udpOptions", "icmpOptions"):
        expected = {"tcp": "tcpOptions", "udp": "udpOptions", "icmp": "icmpOptions"}.get(name)
        if opt_key != expected and rule.get(opt_key) not in (None, {}):
            die(f"{where}: {name}ルールに不適切な{opt_key}が指定されています")

    if name in ("tcp", "udp"):
        csv_row["dst_min"], csv_row["dst_max"] = port_columns(rule, name, where)
    elif name == "icmp":
        options = rule.get("icmpOptions")
        if options is None:
            csv_row["type"], csv_row["code"] = "", ""
        else:
            if not isinstance(options, dict):
                die(f"{where}: icmpOptionsはオブジェクトが必要です")
            check_fields(options, {"type", "code"}, where)
            if "type" not in options:
                die(f"{where}: icmpOptions.typeがありません")
            csv_row["type"] = integer(options["type"], f"{where}: ICMP type", 0, 255)
            code = options.get("code")
            csv_row["code"] = "" if code is None else integer(code, f"{where}: ICMP code", 0, 255)

    return name, csv_row


def read_inputs(args):
    if args.oci_get is not None:
        if args.ingress is not None or args.egress is not None:
            die("--oci-getと--ingress/--egressは同時指定できません")
        loaded = load_json(args.oci_get)
        if not isinstance(loaded, dict):
            die("--oci-getのJSONはオブジェクトが必要です")
        content = loaded.get("data", loaded)
        if not isinstance(content, dict):
            die("get出力のdataはオブジェクトが必要です")
        content = normalize_keys(content)
        if "ingressSecurityRules" not in content or "egressSecurityRules" not in content:
            die("get出力にingress-security-rules/egress-security-rulesがありません")
        ingress = content["ingressSecurityRules"]
        egress = content["egressSecurityRules"]
    else:
        if args.ingress is None or args.egress is None:
            die("--ingressと--egressの両方、または--oci-getを指定してください")
        ingress, egress = load_json(args.ingress), load_json(args.egress)

    if not isinstance(ingress, list) or not isinstance(egress, list):
        die("Ingress/EgressのルールはどちらもJSON配列 [...] である必要があります")
    return ingress, egress


def export_csv(args):
    ingress, egress = read_inputs(args)
    tables = {name: [] for name in CSV_FIELDS}
    for direction, entries in (("ingress", ingress), ("egress", egress)):
        for index, item in enumerate(entries, start=1):
            name, converted = convert_rule(item, direction, index)
            tables[name].append(converted)

    output_dir = args.output_dir
    paths = {name: output_dir / f"{name}.csv" for name in CSV_FIELDS}
    existing = [str(path) for path in paths.values() if path.exists()]
    if existing and not args.force:
        die("上書きを防止しました。次のファイルが存在します。\n  " + "\n  ".join(existing)
            + "\n必要であれば--forceを指定してください")
    if output_dir.exists() and not output_dir.is_dir():
        die(f"出力先がディレクトリではありません: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Prepare every CSV before publishing any output. Publication is per file,
    # not an atomic transaction across all four files.
    staged = {}
    try:
        for name, fields in CSV_FIELDS.items():
            # utf-8-sig makes Japanese descriptions easy to open in Excel.
            with tempfile.NamedTemporaryFile("w", encoding="utf-8-sig", newline="",
                                             dir=output_dir, suffix=".tmp", delete=False) as temp:
                staged[name] = Path(temp.name)
                writer = csv.DictWriter(temp, fieldnames=fields, lineterminator="\n")
                writer.writeheader()
                writer.writerows(tables[name])
        for name in CSV_FIELDS:
            if args.force:
                os.replace(staged[name], paths[name])
            elif os.name == "nt":
                os.rename(staged[name], paths[name])
            else:
                os.link(staged[name], paths[name])
            print(f"{paths[name]}: {len(tables[name])}件")
    finally:
        for temp_path in staged.values():
            temp_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description="OCIセキュリティリストのJSONをtcp/udp/icmp/allのCSVへ逆変換します。OCIへの変更は行いません。"
    )
    parser.add_argument("--ingress", type=Path, help="ingress.json（JSON配列）")
    parser.add_argument("--egress", type=Path, help="egress.json（JSON配列）")
    parser.add_argument("--oci-get", type=Path, help="oci network security-list get のJSON出力")
    parser.add_argument("--output-dir", type=Path, default=Path("csv_export"), help="CSV出力先（既定: csv_export）")
    parser.add_argument("--force", action="store_true", help="既存CSVファイルを上書き")
    args = parser.parse_args()
    try:
        export_csv(args)
    except (ValueError, OSError, csv.Error) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

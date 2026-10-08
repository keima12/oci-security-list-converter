#!/usr/bin/env python3
"""Convert tcp/udp/icmp/all CSV files into OCI Security List rule JSON arrays.

The `description` column is preserved as Unicode text without stripping spaces,
including commas, double quotes and embedded newlines. No OCI API calls are made.
Python 3.9+; only standard library modules are used.
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
    "tcp": ["direction", "cidr", "address_type", "dst_min", "dst_max", "stateless", "description"],
    "udp": ["direction", "cidr", "address_type", "dst_min", "dst_max", "stateless", "description"],
    "icmp": ["direction", "cidr", "address_type", "type", "code", "stateless", "description"],
    "all": ["direction", "cidr", "address_type", "stateless", "description"],
}
PROTOCOLS = {"tcp": "6", "udp": "17", "icmp": "1", "all": "all"}


def checked_int(value, low, high, field):
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise ValueError(f"{field}: {low}～{high}の整数が必要です（入力: {value!r}）")
    number = int(value)
    if not low <= number <= high:
        raise ValueError(f"{field}: {low}～{high}の整数が必要です（入力: {value!r}）")
    return number


def convert_rule(row, protocol):
    direction = row["direction"].strip().lower()
    if direction not in ("ingress", "egress"):
        raise ValueError("directionにはingressまたはegressを指定してください")

    address_type = row.get("address_type", "").strip() or "CIDR_BLOCK"
    if address_type not in ("CIDR_BLOCK", "SERVICE_CIDR_BLOCK"):
        raise ValueError(f"address_typeはCIDR_BLOCKまたはSERVICE_CIDR_BLOCKが必要です: {address_type!r}")
    address = row["cidr"]
    if address_type == "CIDR_BLOCK":
        try:
            network = ipaddress.ip_network(address.strip(), strict=True)
        except ValueError as exc:
            raise ValueError(f"cidrが不正です: {address!r}") from exc
        if protocol == "icmp" and network.version != 4:
            raise ValueError("icmp.csvはIPv4のICMPのみ対応です")
        address = str(network)
    elif not address.strip():
        raise ValueError("SERVICE_CIDR_BLOCKのcidrには空でないサービスCIDRラベルが必要です")
    # Service CIDR labels are opaque strings. Preserve them exactly; no OCI
    # lookup or CIDR parsing is performed for SERVICE_CIDR_BLOCK.

    state_text = row["stateless"].strip().lower()
    if state_text not in ("true", "false"):
        raise ValueError("statelessにはtrueまたはfalseを指定してください")

    rule = {
        "protocol": PROTOCOLS[protocol],
        "isStateless": state_text == "true",
    }
    address_key = "source" if direction == "ingress" else "destination"
    type_key = "sourceType" if direction == "ingress" else "destinationType"
    rule[address_key] = address
    rule[type_key] = address_type

    # Keep the description *exactly* as stored in CSV, including whitespace,
    # non-ASCII characters, quotes, commas and line breaks. Blank means unset.
    description = row["description"]
    if description:
        rule["description"] = description

    if protocol in ("tcp", "udp"):
        minimum, maximum = row["dst_min"].strip().lower(), row["dst_max"].strip().lower()
        if minimum == "all" and maximum == "all":
            pass  # No tcpOptions/udpOptions means all ports.
        elif minimum == "all" or maximum == "all":
            raise ValueError("全ポート指定はdst_minとdst_maxの両方をallにしてください")
        else:
            lo = checked_int(minimum, 1, 65535, "dst_min")
            hi = checked_int(maximum, 1, 65535, "dst_max")
            if lo > hi:
                raise ValueError("dst_minはdst_max以下にしてください")
            opt_key = "tcpOptions" if protocol == "tcp" else "udpOptions"
            rule[opt_key] = {"destinationPortRange": {"min": lo, "max": hi}}
    elif protocol == "icmp":
        icmp_type = row["type"].strip()
        code = row["code"].strip()
        if not icmp_type and not code:
            pass  # No icmpOptions means all ICMP types and codes.
        elif not icmp_type:
            raise ValueError("ICMP codeを指定する場合はtypeも指定してください")
        else:
            options = {"type": checked_int(icmp_type, 0, 255, "type")}
            if code:
                options["code"] = checked_int(code, 0, 255, "code")
            rule["icmpOptions"] = options

    return direction, rule


def read_csv(path, protocol):
    result = []
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream, strict=True)
        actual = reader.fieldnames
        if actual is None:
            raise ValueError(f"{path}: CSVのヘッダー行がありません")
        if len(actual) != len(set(actual)):
            raise ValueError(f"{path}: CSVヘッダーが重複しています")
        # address_type was added later; old CSV headers remain supported.
        required = set(CSV_FIELDS[protocol]) - {"address_type"}
        missing = required - set(actual)
        unexpected = set(actual) - set(CSV_FIELDS[protocol])
        if missing or unexpected:
            raise ValueError(
                f"{path}: CSVヘッダー不一致（不足={sorted(missing)}, 余分={sorted(unexpected)}）"
            )
        for row in reader:
            line_no = reader.line_num
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"{path}:{line_no}: 列数がCSVヘッダーと一致しません")
            if not any(value for value in row.values()):
                continue
            try:
                result.append(convert_rule(row, protocol))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: {exc}") from exc
    return result


def convert_all(input_dir, output_dir, force):
    rules = {"ingress": [], "egress": []}
    for protocol in CSV_FIELDS:
        path = input_dir / f"{protocol}.csv"
        if not path.is_file():
            raise ValueError(f"入力CSVがありません: {path}")
        for direction, rule in read_csv(path, protocol):
            rules[direction].append(rule)

    paths = {key: output_dir / f"{key}.json" for key in rules}
    existing = [str(path) for path in paths.values() if path.exists()]
    if existing and not force:
        raise ValueError("既存ファイルを上書きしません: " + ", ".join(existing)
                         + "（上書き時は--forceを指定）")
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"出力先はディレクトリではありません: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Stage both files before publishing the resulting JSON.
    staged = {}
    try:
        for direction in ("ingress", "egress"):
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n",
                                             dir=output_dir, suffix=".tmp", delete=False) as temp:
                staged[direction] = Path(temp.name)
                json.dump(rules[direction], temp, ensure_ascii=False, indent=2)
                temp.write("\n")
        for direction in ("ingress", "egress"):
            if force:
                os.replace(staged[direction], paths[direction])
            elif os.name == "nt":
                # Windows rename fails if the destination already exists.
                os.rename(staged[direction], paths[direction])
            else:
                # Exclusive creation also protects against a destination created
                # after the initial existence check. Files are published one by one.
                os.link(staged[direction], paths[direction])
            print(f"{paths[direction]}: {len(rules[direction])}件")
    finally:
        for temp_path in staged.values():
            temp_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="OCI Security List: 4種のCSVをIngress/Egress JSONへ変換")
    parser.add_argument("--input-dir", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--force", action="store_true", help="既存のJSONを上書きする")
    args = parser.parse_args()
    try:
        convert_all(args.input_dir, args.output_dir, args.force)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

# OCIセキュリティ・リスト CSV ⇔ JSON変換ツール

OCIセキュリティ・リストのIngress/Egressルールを、編集しやすい4種類のCSVとOCI CLI入力用JSON配列の間で変換するPythonスクリプトです。`oci network security-list get`で取得した標準JSONからCSVへの変換にも対応します。

変換スクリプト自体はOCI APIを呼び出しません。生成したJSONをOCIに適用する操作は、利用者が内容を確認した後に別途実行します。

## 必要な環境

- Python 3.9以上。Pythonの標準ライブラリだけを使用し、追加パッケージは不要です。
- OCIから取得・OCIに反映する場合のみ、設定済みのOCI CLIと対象リソースに対する権限が必要です。
- 以下の例はリポジトリのルートディレクトリで実行します。環境に応じて`python`を`python3`または`py -3`に読み替えてください。

## ファイル構成

```text
oci_security_list_csv_to_json.py  CSV → ingress.json / egress.json
oci_security_list_json_to_csv.py JSON → tcp.csv / udp.csv / icmp.csv / all.csv
examples/
  csv/                          4種類の合成CSV例
  json/                         OCI CLI入力用Ingress/Egress配列の合成例
  oci-get.json                  dataラッパー・ハイフン区切りキーの合成例
```

公開例のCIDRは`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`配下の文書用アドレスのみです。実環境のOCID・資格情報・内部CIDRを含みません。`examples/oci-get.json`は形式説明用に作成したデータであり、実環境から取得したJSONではありません。リソースIDなどのメタデータは例から省いています。

## まず合成例で試す

### CSVからJSONへ

```shell
python oci_security_list_csv_to_json.py --input-dir examples/csv --output-dir local-data/from-csv
```

`local-data/from-csv/ingress.json`と`egress.json`が作成されます。出力は`isStateless`、`tcpOptions`、`destinationPortRange`などcamelCaseのキーを使用したJSON配列です。

### OCI CLI入力用JSON配列からCSVへ

```shell
python oci_security_list_json_to_csv.py --ingress examples/json/ingress.json --egress examples/json/egress.json --output-dir local-data/from-arrays
```

### get形式のJSONからCSVへ、続いてJSONへ戻す

```shell
python oci_security_list_json_to_csv.py --oci-get examples/oci-get.json --output-dir local-data/roundtrip-csv
python oci_security_list_csv_to_json.py --input-dir local-data/roundtrip-csv --output-dir local-data/roundtrip-json
```

各コマンドの終了コードが0であることを確認してください。不正な入力や未対応のルールは終了コード1で停止します。再実行で既存の出力ファイルを上書きする場合のみ、それぞれのコマンドに`--force`を追加します。

JSON → CSV → JSONの往復では、対応範囲のルールの意味と説明文を保持します。ただし、ルールはTCP、UDP、ICMP、ALLの順にまとまるため、元JSONの配列順は変わる場合があります。省略可能なキー・`null`・CIDRの表記も整理されるため、元のJSONとのバイト単位の一致は保証しません。空の説明文と未設定の説明文は区別しません。

## 実環境のget出力を保存して変換する

get出力にはOCID、CIDR、説明文などの実環境情報が含まれる可能性があります。公開するリポジトリや例ファイルとは別の作業場所で扱い、取得ファイルや変換結果をそのまま公開しないでください。

### Bash

```bash
set -euo pipefail
mkdir -p local-data
SECURITY_LIST_ID='REPLACE_WITH_SECURITY_LIST_OCID'
PYTHONIOENCODING=utf-8 oci network security-list get \
  --security-list-id "$SECURITY_LIST_ID" \
  --output json > local-data/security-list-get.json

python oci_security_list_json_to_csv.py \
  --oci-get local-data/security-list-get.json \
  --output-dir local-data/csv
```

OCI CLIが失敗した場合は`set -e`で後続処理を停止します。失敗時には出力先に空または不完全なファイルが残る可能性があるため、成功した取得結果だけを使用してください。

### PowerShell

Windows PowerShellでの単純な`>`リダイレクトはUTF-16になる場合があります。以下はOCI CLIの成功を確認してから、明示的にUTF-8で保存する例です。

```powershell
$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
New-Item -ItemType Directory -Path local-data -Force | Out-Null
$securityListId = 'REPLACE_WITH_SECURITY_LIST_OCID'

$jsonText = & oci network security-list get --security-list-id $securityListId --output json
if ($LASTEXITCODE -ne 0) {
    throw 'OCI CLIの取得に失敗しました。変換を中止します。'
}
$jsonPath = Join-Path (Get-Location).Path 'local-data/security-list-get.json'
[System.IO.File]::WriteAllText(
    $jsonPath,
    ($jsonText -join [Environment]::NewLine),
    [System.Text.UTF8Encoding]::new($false)
)

python oci_security_list_json_to_csv.py --oci-get $jsonPath --output-dir local-data/csv
if ($LASTEXITCODE -ne 0) {
    throw 'JSONからCSVへの変換に失敗しました。後続処理を中止します。'
}
```

`--oci-get`は標準レスポンスの`data`ラッパー付きJSONと、`--query data`で取り出したルールを含むオブジェクトの両方を受け付けます。キーはハイフン区切り・camelCaseのどちらも扱います。`--oci-get`と`--ingress`/`--egress`は同時指定できません。配列入力の場合は`--ingress`と`--egress`の両方を指定します。

get出力のリソースOCID、コンパートメントOCID、表示名、タグ、ETagなどのメタデータはCSV・生成JSONに出力しません。ルール内のCIDRと説明文は保持するため、変換は機密情報の匿名化を目的とした処理ではありません。

## CSVの形式

CSV → JSONでは、入力ディレクトリに4枚のCSVがすべて必要です。あるプロトコルのルールがない場合は、そのCSVをヘッダー行だけにします。列の不足・余分な列・重複列はエラーになります。

| ファイル | ヘッダー |
| --- | --- |
| `tcp.csv` | `direction,cidr,dst_min,dst_max,stateless,description` |
| `udp.csv` | `direction,cidr,dst_min,dst_max,stateless,description` |
| `icmp.csv` | `direction,cidr,type,code,stateless,description` |
| `all.csv` | `direction,cidr,stateless,description` |

| 列 | 指定方法 |
| --- | --- |
| `direction` | `ingress`または`egress`。Ingressでは`cidr`を`source`、Egressでは`destination`に変換します。 |
| `cidr` | 有効なIPv4/IPv6ネットワークのCIDR。ホストビットが立った値はエラーです。例：`192.0.2.1/24`ではなく`192.0.2.0/24`。 |
| `dst_min`,`dst_max` | このツールでは1～65535の整数、かつ`dst_min <= dst_max`。単一ポートは同じ値を指定します。両列を`all`にすると宛先全ポートです。空欄や片方だけの`all`はエラーです。 |
| `type`,`code` | IPv4 ICMPの0～255の整数。タイプを指定してコードを空欄にすると、そのタイプの全コード。両方空欄にすると全ICMPタイプ・コード。コードだけの指定はエラーです。 |
| `stateless` | `true`または`false`。`false`はステートフルです。 |
| `description` | 任意の説明文。日本語、空白、カンマ、引用符、改行を保持します。空欄は説明未設定として扱います。 |

数値として0～255を受け付けるICMPタイプ・コードにも、プロトコル上の割当てや有効な組合せがあります。OCIへの反映前に必要な値を確認してください。

入力CSV・JSONはUTF-8（BOMの有無はどちらも可）です。JSON → CSVの出力はUTF-8 BOM付きで、CSV → JSONの出力はUTF-8です。カンマ・引用符・改行を含む説明文は、通常のCSV規則に従って引用します。`examples/csv/icmp.csv`に改行を含む説明の例があります。

## 対応範囲と制限

- Ingress/Egress、TCP（6）、UDP（17）、IPv4 ICMP（1）、ALL（`all`）に対応します。
- TCP/UDP/ALLはIPv4・IPv6 CIDRに対応します。ICMPv6（58）は未対応です。
- アドレス種別は`CIDR_BLOCK`に対応します。`SERVICE_CIDR_BLOCK`は未対応です。
- TCP/UDPは宛先ポート範囲だけを扱います。送信元ポート制限（`sourcePortRange`）を含むルールは未対応です。
- その他の数値プロトコルやCSVで表現できない項目を含むルールは、黙って落とさず明示的なエラーにします。
- ポート1～65535はこのツールの対応範囲です。ポート0をOCI自体が受け付けないと断定するものではありません。
- NSGのJSON、複数リソースの`list`出力、Terraformの構成ファイルは対象外です。

変換エラーが出た場合は、未対応ルールを削除してそのまま全体を反映するのではなく、対象の通信要件と反映方法を確認してください。

## OCIへ適用する際の注意

**`oci network security-list update`に渡した方向のルール配列は、その方向の既存ルール全体を置き換えます。追加だけを行う操作ではありません。** 空のJSON配列`[]`を渡すと、その方向のルールを空にします。方向の指定を省略した場合は、その方向を更新しません。

1. 反映先のセキュリティ・リストをgetで取得し、復旧用のバックアップを保管します。
2. 生成した`ingress.json`と`egress.json`を確認します。管理接続やPath MTU Discoveryに必要な既存ルールも確認します。
3. 同時変更を避けるため、反映先の最新ETagを取得し、`--if-match`を使います。
4. 検証環境で確認した後に反映します。

以下はBashの手動適用例です。反映先のOCIDは利用者が設定してください。コピー元と反映先が異なる場合、コピー元のETagは使用できません。

```bash
set -euo pipefail
TARGET_SECURITY_LIST_ID='REPLACE_WITH_TARGET_SECURITY_LIST_OCID'
PYTHONIOENCODING=utf-8 oci network security-list get \
  --security-list-id "$TARGET_SECURITY_LIST_ID" \
  --output json > local-data/target-backup.json
ETAG="$(python -c 'import json; print(json.load(open("local-data/target-backup.json", encoding="utf-8-sig"))["etag"])')"

oci network security-list update \
  --security-list-id "$TARGET_SECURITY_LIST_ID" \
  --if-match "$ETAG" \
  --ingress-security-rules file://local-data/from-csv/ingress.json \
  --egress-security-rules file://local-data/from-csv/egress.json
```

ETag不一致の場合は対象が変更されています。再取得して内容を見直し、最新状態と生成結果を比較してください。getレスポンス全体を`--ingress-security-rules`や`--egress-security-rules`に渡すことはできません。これらの引数には、それぞれのJSON配列を渡します。

ステートレスルールでは戻り通信を許可する対応ルールも必要です。ステートフルとステートレスが同じ通信に一致すると、ステートレスが優先されます。変換成功だけでは、通信要件・ルーティング・OS側ファイアウォールまで正しいことは確認できません。

実環境のOCI CLIによる取得・反映試験は実施していません。ローカル変換の検証とOCI環境での適用確認は分けて扱ってください。

## 動作確認

```shell
python -m unittest discover -s tests -v
```

26件の自動テストで、両方向・4種類のプロトコル・get形式・説明文の往復、未対応項目の検出、不正なCSV/JSON、重複キー、上書き防止、出力準備中の失敗時の既存ファイル保護を確認しています。公開準備時はWindows/Python 3.13で成功しました。Python 3.9以上向けに実装していますが、全バージョン・全OSでの実行試験は行っていません。

出力はすべてのファイルを一時書込みしてから、1ファイルずつ確定します。複数ファイル全体を一括で更新する保証はありません。出力の確定中にディスク障害などが発生した場合は、別の空ディレクトリで再実行し、出力一式を確認してください。Windows以外では、`--force`なしの出力にハードリンクを使うため、対応するファイルシステム上の保存先を使用してください。

## ExcelなどでCSVを開く場合

説明文が`=`、`+`、`-`、`@`などで始まる場合、表計算ソフトが数式として解釈する可能性があります。外部から取得したCSVはダブルクリックで開かず、取り込み時に説明列を文字列として指定するなど、使用するソフトに合わせて対処してください。必要に応じてテキストエディターで確認してください。

このツールは説明文を保持するため、先頭へのアポストロフィ追加などの自動変更は行いません。CSVの引用符だけでは数式の解釈を防げません。Excelでの保存時には、UTF-8 CSV、列名、CIDR、整数値、説明文の改行が維持されていることも確認してください。

## ライセンス

[MIT License](LICENSE)で公開しています。著作権表示とライセンス文を保持することで、利用・改変・再配布が可能です。本ソフトウェアは無保証で提供します。詳細な条件は同梱の`LICENSE`を参照してください。

## 参考情報

- [Oracle公式：セキュリティ・リスト（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/Network/Concepts/securitylists.htm)
- [Oracle公式：セキュリティ・ルール（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/Network/Concepts/securityrules.htm)
- [Oracle公式：CLIの開始・レスポンス例（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/GSG/Tasks/gettingstartedwiththeCLI.htm)
- [OCI CLI：network security-list get](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/get.html)
- [OCI CLI：network security-list update](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/update.html)
- [OCI SDK：IngressSecurityRule（説明文を含む現行モデル）](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.IngressSecurityRule.html)
- [OCI SDK：EgressSecurityRule](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.EgressSecurityRule.html)
- [OCI SDK：IcmpOptions](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.IcmpOptions.html)
- [OCI SDK：PortRange](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.PortRange.html)

日本語の一般概念ページには説明文をNSG専用とする記載がありますが、現行Ingress/Egressモデルは`description`を持ちます。このツールの説明文対応は現行モデルに基づきます。

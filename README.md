# OCIセキュリティ・リスト CSV ⇔ JSON変換ツール

OCIセキュリティ・リストのIngress/Egressルールを、編集しやすいCSVとOCI CLI入力用JSON配列の間で変換するPythonスクリプトです。通常のCIDR（`CIDR_BLOCK`）はプロトコル別の4枚、サービスCIDR（`SERVICE_CIDR_BLOCK`）は専用の`service.csv`に出力します。`oci network security-list get`で取得した標準JSONからCSVへの変換にも対応します。CSVに変換できないルールは、CSV出力先と同じフォルダの`unconverted-rules.json`に原文と理由を保存します。

変換スクリプト自体はOCI APIを呼び出しません。生成したJSONをOCIに適用する操作は、利用者が内容を確認した後に別途実行します。

## 必要な環境

- Python 3.9以上。Pythonの標準ライブラリだけを使用し、追加パッケージは不要です。
- OCIから取得・OCIに反映する場合のみ、設定済みのOCI CLIと対象リソースに対する権限が必要です。
- 以下の例はリポジトリのルートディレクトリで実行します。環境に応じて`python`を`python3`または`py -3`に読み替えてください。

## ファイル構成

```text
oci_security_list_csv_to_json.py  CSV → ingress.json / egress.json
oci_security_list_json_to_csv.py JSON → tcp.csv / udp.csv / icmp.csv / all.csv / service.csv
                                     + unconverted-rules.json（結果・未変換ルール）
examples/
  csv/                          プロトコル別4枚とサービス専用CSVの合成例
  json/                         OCI CLI入力用Ingress/Egress配列の合成例
  oci-get.json                  dataラッパー・ハイフン区切りキーの合成例
```

公開例のIP CIDRは`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`配下の文書用アドレスのみです。サービスCIDRの例にはOracle公式資料にある公開ラベルを使用しています。実環境のOCID・資格情報・内部CIDRを含みません。`examples/oci-get.json`は形式説明用に作成したデータであり、実環境から取得したJSONではありません。リソースIDなどのメタデータは例から省いています。

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

各コマンドの終了コードが0であることを確認してください。JSON → CSVで未対応・不正なルールがある場合は、変換できるルールのCSVと未変換JSONを保存したうえで終了コード1を返します。CSV → JSONは不正なCSVや未解決の未変換JSONがあれば停止します。再実行で既存の出力ファイルを上書きする場合のみ、それぞれのコマンドに`--force`を追加します。

JSON → CSV → JSONの往復では、対応範囲のルールの意味と説明文を保持します。ただし、ルールはTCP、UDP、ICMP、ALLの順にまとまり、同じプロトコルでは従来4CSVの行、`service.csv`の行の順になるため、元JSONの配列順は変わる場合があります。省略可能なキー・`null`・CIDRの表記も整理されるため、元のJSONとのバイト単位の一致は保証しません。空の説明文と未設定の説明文は区別しません。

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

正常変換時、get出力のリソースOCID、コンパートメントOCID、表示名、タグ、ETagなどのメタデータはCSV・生成JSONに出力しません。ルール内のCIDRと説明文は保持するため、変換は機密情報の匿名化を目的とした処理ではありません。入力全体の変換に失敗した場合のJSONレポートには、入力ファイルの内容を保管するため、メタデータも含まれる可能性があります。

## CSVの形式

CSV → JSONでは、入力ディレクトリにプロトコル別の4枚のCSVがすべて必要です。あるプロトコルのルールがない場合は、そのCSVをヘッダー行だけにします。`service.csv`は任意で、存在する場合は追加で読み込みます。従来4枚では`address_type`以外の列の不足・余分な列・重複列はエラーです。`service.csv`では下表の全列が必要です。

| ファイル | ヘッダー |
| --- | --- |
| `tcp.csv` | `direction,cidr,address_type,dst_min,dst_max,stateless,description` |
| `udp.csv` | `direction,cidr,address_type,dst_min,dst_max,stateless,description` |
| `icmp.csv` | `direction,cidr,address_type,type,code,stateless,description` |
| `all.csv` | `direction,cidr,address_type,stateless,description` |
| `service.csv` | `direction,cidr,protocol,dst_min,dst_max,type,code,stateless,description` |

JSON → CSVは常に5枚のCSVを出力し、該当ルールがないCSVはヘッダー行のみになります。従来4枚のCSVは`address_type`列を出力します。CSV → JSONは、この列がない旧形式の4CSVも受け付け、列がない場合・値が空欄の場合は`CIDR_BLOCK`として扱います。従来4CSVに`SERVICE_CIDR_BLOCK`を指定する前の版の形式も引き続き読み込めます。`service.csv`には`address_type`列を設けず、全行を`SERVICE_CIDR_BLOCK`として扱います。新しいCSVを読み込む際は、両スクリプトを最新版に更新してください。同じルールを従来4CSVと`service.csv`の両方に書くと二重に取り込まれるため、どちらか一方に記載してください。

| 列 | 指定方法 |
| --- | --- |
| `direction` | `ingress`または`egress`。Ingressでは`cidr`を`source`、Egressでは`destination`に変換します。 |
| `cidr` | `CIDR_BLOCK`では有効なIPv4/IPv6ネットワークのCIDR。ホストビットが立った値はエラーです。例：`192.0.2.1/24`ではなく`192.0.2.0/24`。`SERVICE_CIDR_BLOCK`ではサービスCIDRラベル文字列。 |
| `address_type` | `CIDR_BLOCK`または`SERVICE_CIDR_BLOCK`。Ingressの`sourceType`、Egressの`destinationType`に対応します。前後の空白を除いて大文字の値を指定します。空欄・列省略は`CIDR_BLOCK`。未知の種別はエラーです。 |
| `protocol` | `service.csv`専用。`tcp`、`udp`、`icmp`、`all`のいずれか。 |
| `dst_min`,`dst_max` | このツールでは1～65535の整数、かつ`dst_min <= dst_max`。単一ポートは同じ値を指定します。両列を`all`にすると宛先全ポートです。空欄や片方だけの`all`はエラーです。 |
| `type`,`code` | IPv4 ICMPの0～255の整数。タイプを指定してコードを空欄にすると、そのタイプの全コード。両方空欄にすると全ICMPタイプ・コード。コードだけの指定はエラーです。 |
| `stateless` | `true`または`false`。`false`はステートフルです。 |
| `description` | 任意の説明文。日本語、空白、カンマ、引用符、改行を保持します。空欄は説明未設定として扱います。 |

数値として0～255を受け付けるICMPタイプ・コードにも、プロトコル上の割当てや有効な組合せがあります。OCIへの反映前に必要な値を確認してください。

入力CSV・JSONはUTF-8（BOMの有無はどちらも可）です。JSON → CSVの出力はUTF-8 BOM付きで、CSV → JSONの出力はUTF-8です。カンマ・引用符・改行を含む説明文は、通常のCSV規則に従って引用します。`examples/csv/icmp.csv`に改行を含む説明の例があります。

### サービス専用CSVを指定する

`service.csv`の`cidr`列には`Service.cidrBlock`の値を指定します。サービスのOCIDやコンソールの表示名ではありません。たとえば次のTCP Egress行は、宛先サービスラベルと宛先ポート443を保持します。

```csv
direction,cidr,protocol,dst_min,dst_max,type,code,stateless,description
egress,all-phx-services-in-oracle-services-network,tcp,443,443,,,false,公開サービスラベルを使った形式例
```

この例のラベルはPHXリージョンの公開例です。そのまま別リージョンに適用せず、利用するリージョンで取得したサービス一覧の`cidr-block`を使用してください。取得例（リージョンは利用環境に合わせて変更）：

```shell
oci network service list --all --region ap-tokyo-1 --output json
```

`service.csv`はTCP/UDP行で`type`・`code`を空欄、ICMP行で`dst_min`・`dst_max`を空欄、ALL行ですべてのポート・ICMP列を空欄にします。使用しない列に値がある場合はCSV → JSONでエラーにします。

JSON → CSVでは`sourceType`/`destinationType`（get形式では`source-type`/`destination-type`）が`SERVICE_CIDR_BLOCK`のルールを`service.csv`だけに出力し、従来4CSVには重複出力しません。CSV → JSONではサービス種別とラベルに戻します。`examples/csv/service.csv`、`examples/json/ingress.json`、`examples/json/egress.json`、`examples/oci-get.json`に両方向のサービスCIDR形式例があります。

サービスCIDRラベルはIP CIDRとして解析せず、空・空白のみの値を拒否し、それ以外の文字列は変更せず保持します。ラベルが実在するか、対象リージョンで利用できるか、通信要件・経路・サービスとの対応が正しいかは、このローカル変換では確認しません。不要な空白なども利用者が確認してください。サービスCIDRルールの変換成功は、Oracleサービスからの新規接続や通信全体の成立を保証しません。

## 変換できないルールのJSON保存

JSON → CSVは、CSVと同じ出力フォルダにUTF-8の`unconverted-rules.json`を出力します。

| `status` | 出力内容 | 終了コード |
| --- | --- | --- |
| `complete` | 5枚のCSVと、未変換配列が空のJSONレポート | 0 |
| `partial` | 変換できたルールの5枚のCSVと、未変換ルールを含むJSONレポート | 1 |
| `failed` | 入力読込・JSON構文・入力全体の形式や書込みの失敗を記録したJSONレポート。入力確認時点の失敗ではCSVを作成しません | 1 |

未対応プロトコル・送信元ポート制限・未知のアドレス種別・不正なルールなどは、方向別の`ingress`/`egress`配列に`index`（元の方向別配列内の1始まり位置）、`error`（理由）、`rule`（元のルール）を保存します。get形式のハイフン区切りキーや未対応項目も保持し、対応できる他のルールの変換は続けます。入力全体を解析できない場合は、`error`と`inputs`に入力ファイル名・元テキストを保存します。UTF-8で読めない入力はBase64で保存し、ファイル自体を読み出せない場合は読込エラーを記録します。出力先へ書き込めない場合はJSON保存もできないため、標準エラーに理由を表示します。

`unconverted-rules.json`はOCI CLIへ渡すルール配列ではなく、未変換内容の保管・確認用です。CSV → JSONはこのファイルが存在する場合、`format_version`が1、`status`が`complete`、両方向の未変換配列が空の場合にだけ進みます。`partial`・`failed`や不正なレポートがあれば、不完全なルール配列の生成を防ぐため停止します。レポートがない従来CSVは引き続き読み込めます。

未変換ルールを確認し、元の入力や変換対応・適用方法を解決してから再変換してください。レポートを削除するだけで一部のCSVを全ルールとして反映すると、既存ルールを失う可能性があります。既存の出力を更新する場合は`--force`を指定します。成功した再変換は空の`complete`レポートで以前の未変換情報も更新するため、古い失敗レポートを残しません。入力確認時点や一時書込み中の失敗では既存CSVを更新せず、同じフォルダの失敗レポートによりCSV → JSONは停止します。出力確定中の障害ではCSVの一部が更新済みの場合があるため、出力一式を確認し、別の空フォルダで再実行してください。

レポートには実環境のルールや元入力が含まれるため、取得JSONと同様に公開しないでください。`unconverted-rules.json`は`.gitignore`の対象です。

## 対応範囲と制限

- Ingress/Egress、TCP（6）、UDP（17）、IPv4 ICMP（1）、ALL（`all`）に対応します。
- TCP/UDP/ALLはIPv4・IPv6 CIDRに対応します。ICMPv6（58）は未対応です。
- アドレス種別は`CIDR_BLOCK`と`SERVICE_CIDR_BLOCK`に両方向で対応します。サービスCIDRもTCP/UDP/IPv4 ICMP/ALLの形式を変換できます。サービスラベルの実在確認やIP範囲への展開は行いません。
- TCP/UDPは宛先ポート範囲だけを扱います。送信元ポート制限（`sourcePortRange`）を含むルールは未対応です。
- その他の数値プロトコルやCSVで表現できない項目を含むルールは、JSON → CSVでは未変換JSONに保存します。CSV → JSONでは未解決のレポートがあれば停止します。
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

57件の自動テストで、両方向・4種類のプロトコル・get形式・説明文の往復、サービス専用CSV、IP CIDRとの分離、旧CSVとの互換性、未変換JSONの原文保持、入力全体の失敗保存、不正レポートの検出、上書き防止、出力準備中の失敗時の既存ファイル保護を確認しています。Windows/Python 3.13で成功しました。Python 3.9以上向けに実装していますが、全バージョン・全OSでの実行試験は行っていません。

出力はすべてのファイルを一時書込みしてから、1ファイルずつ確定します。複数ファイル全体を一括で更新する保証はありません。レポートだけで出力一式の完全性を保証するものではありません。出力の確定中にディスク障害などが発生した場合は、別の空ディレクトリで再実行し、出力一式を確認してください。Windows以外では、`--force`なしの出力にハードリンクを使うため、対応するファイルシステム上の保存先を使用してください。

## ExcelなどでCSVを開く場合

説明文やサービスCIDRラベル（`cidr`列）が`=`、`+`、`-`、`@`などで始まる場合、表計算ソフトが数式として解釈する可能性があります。外部から取得したCSVはダブルクリックで開かず、取り込み時に`description`列と`cidr`列を文字列として指定するなど、使用するソフトに合わせて対処してください。必要に応じてテキストエディターで確認してください。

このツールは説明文とサービスCIDRラベルを保持するため、先頭へのアポストロフィ追加などの自動変更は行いません。CSVの引用符だけでは数式の解釈を防げません。Excelでの保存時には、UTF-8 CSV、列名、アドレス種別、CIDRやサービスCIDRラベル、整数値、説明文の改行が維持されていることも確認してください。

## ライセンス

[MIT License](LICENSE)で公開しています。著作権表示とライセンス文を保持することで、利用・改変・再配布が可能です。本ソフトウェアは無保証で提供します。詳細な条件は同梱の`LICENSE`を参照してください。

## 参考情報

- [Oracle公式：セキュリティ・リスト（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/Network/Concepts/securitylists.htm)
- [Oracle公式：セキュリティ・ルール（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/Network/Concepts/securityrules.htm)
- [Oracle公式：サービス・ゲートウェイとサービスCIDRラベル（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/Network/Tasks/servicegateway.htm)
- [Oracle公式：CLIの開始・レスポンス例（日本語）](https://docs.oracle.com/ja-jp/iaas/Content/GSG/Tasks/gettingstartedwiththeCLI.htm)
- [OCI CLI：network security-list get](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/get.html)
- [OCI CLI：network security-list update](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/update.html)
- [OCI CLI：network service list](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/service/list.html)
- [OCI SDK：IngressSecurityRule（説明文を含む現行モデル）](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.IngressSecurityRule.html)
- [OCI SDK：EgressSecurityRule](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.EgressSecurityRule.html)
- [OCI SDK：Service（cidrBlockの値）](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.Service.html)
- [OCI SDK：IcmpOptions](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.IcmpOptions.html)
- [OCI SDK：PortRange](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.PortRange.html)

日本語の一般概念ページには説明文をNSG専用とする記載がありますが、現行Ingress/Egressモデルは`description`を持ちます。このツールの説明文対応は現行モデルに基づきます。

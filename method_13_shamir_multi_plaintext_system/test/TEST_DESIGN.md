# シャミア秘密分散法による複数平文復号システム - テスト設計書

## 1. テスト設計方針

### 1.1 テスト設計の目的

このテスト設計は、シャミア秘密分散法による複数平文復号システムが正確に動作することを検証するためのものです。テストは以下の原則に基づいて設計されています：

1. **実際の CLI を使用**: テストは実際のコマンドラインインターフェースを使用して実行します
2. **バックドア・バイパスの排除**: 実際のシステム値を使用し、ショートカットなしでテストを実行します
3. **暗号学的安全性の確認**: 統計的検証、パターン分析などの暗号学的安全性テストを含めます
4. **段階的テスト拡張**: 現状は「暗号書庫生成」のみですが、将来的には「暗号書庫更新」「暗号書庫読取」も含めます
5. **再現可能な結果**: 各テストは再現可能であり、テスト結果は明確なフォーマットで報告されます
6. **ファイル分割と単一責務**: 各ファイルは 300 行を目安に分割し、単一責務の原則に従って実装します
7. **設定による機能制御**: テストケースや分析処理は設定ファイルにより個別に有効/無効化できます
8. **1 機能 1 ファイル原則**: 各テストケースは個別ファイルとして実装し、各分析機能も個別ファイルとして実装します

### 1.2 テスト範囲

現在のテスト範囲：

- ✅ 暗号書庫生成（createCryptoStorage）

将来対応予定：

- ⬜ 暗号書庫更新（updateCryptoStorage）
- ⬜ 暗号書庫読取（readCryptoStorage）

### 1.3 外部管理ファイル

- **test_passwords.txt**: テスト用パスワードファイルは運用側でメンテナンスされます。このファイルは、テスト実行時に使用されるパスワードのリストを含んでおり、運用チームがセキュリティポリシーに従って管理・更新します。テストコードはこのファイルからパスワードを読み込むことでテストを実行します。

### 1.4 設定による制御

以下の機能は設定ファイル（`test_config.json`）により個別に有効/無効化できます：

1. **テストケース制御**：

   - 各テストケースは設定ファイルで有効/無効を切り替え可能
   - テストケースをグループ化して一括で有効/無効切り替えも可能
   - 例: `{"test_cases": {"CC-001": true, "CC-002": false, ...}}`

2. **分析処理制御**：
   - 各分析処理も設定ファイルで有効/無効を切り替え可能
   - リソース消費の大きい分析は必要な場合のみ実行可能
   - 例: `{"analytics": {"key_length": true, "key_randomness": true, ...}}`

## 2. ディレクトリ構成

```
method_13_shamir_multi_plaintext_system/test/
├── TEST_DESIGN.md           # このテスト設計ドキュメント
├── TEST_SPECIFICATION.md    # 詳細なテスト仕様
├── test_report_template.md  # テストレポートテンプレート
├── test_passwords.txt       # テスト用パスワードリスト（運用側にてメンテナンス）
├── test_config.json         # テスト設定ファイル
├── test_runner.py           # メインテスト実行スクリプト
├── test_report/             # テスト実行結果レポート保存先
│   └── ...
├── utils/                   # テスト用ユーティリティ
│   ├── __init__.py
│   ├── cli_runner.py        # CLI実行ユーティリティ
│   ├── config_loader.py     # 設定ファイル読み込みユーティリティ
│   ├── password_manager.py  # パスワード管理ユーティリティ
│   ├── report_generator.py  # レポート生成ユーティリティ
│   └── test_logger.py       # テストログ出力ユーティリティ
├── analysis/                # 分析モジュール（1機能1ファイル）
│   ├── __init__.py
│   ├── key_length_analyzer.py      # キー長分析
│   ├── key_randomness_analyzer.py  # キーのランダム性分析
│   ├── key_uniqueness_analyzer.py  # キーの一意性分析
│   ├── partition_overlap_analyzer.py  # パーティション重複分析
│   ├── share_ratio_analyzer.py     # シェア比率分析
│   ├── share_distribution_analyzer.py  # シェア分布分析
│   ├── execution_time_analyzer.py  # 実行時間分析
│   └── memory_usage_analyzer.py    # メモリ使用量分析
└── test_cases/              # テストケース（1テストケース1ファイル）
    ├── __init__.py
    ├── base_test.py         # テスト基底クラス
    ├── crypto_storage_creation/  # 暗号書庫生成テスト
    │   ├── __init__.py
    │   ├── test_cc_001_basic_creation.py      # 基本生成テスト
    │   ├── test_cc_002_multiple_creation.py   # 複数回生成テスト
    │   ├── test_cc_003_password_change.py     # パスワード変更テスト
    │   ├── test_cc_004_verify_option.py       # 検証オプションテスト
    │   ├── test_cs_001_map_key_length.py      # パーティションマップキー長テスト
    │   ├── test_cs_002_partition_separation.py # パーティション分離検証
    │   ├── test_cs_003_invalid_input.py       # 異常入力検証
    │   └── test_cs_004_map_key_strength.py    # パーティションマップキー強度検証
    ├── crypto_storage_update/  # 暗号書庫更新テスト（将来追加）
    │   ├── __init__.py
    │   └── ...
    └── crypto_storage_read/  # 暗号書庫読取テスト（将来追加）
        ├── __init__.py
        └── ...
```

## 3. テスト実行フロー

### 3.1 基本的なテスト実行フロー

1. `test_runner.py`を実行
2. `config_loader.py`で設定ファイル（`test_config.json`）を読み込み
3. 設定に基づいて実行するテストケースを決定
4. テストを実行
5. テスト結果を収集
6. 設定に基づいて有効化された分析処理を実行
7. レポートを生成（`report_generator.py`を使用）して`test_report`ディレクトリに保存

### 3.2 CLI コマンド実行方法

テストは実際の CLI コマンドを実行することで行います。`cli_runner.py`は以下の機能を提供します：

```python
def run_cli_command(command, args, input_data=None):
    """
    CLIコマンドを実行し、結果を取得する

    Args:
        command: 実行するCLIコマンド（例: 'create_storage.py'）
        args: コマンドライン引数の辞書
        input_data: 標準入力に送るデータ（オプション）

    Returns:
        (exit_code, stdout, stderr): 終了コード、標準出力、標準エラー出力
    """
    # CLIコマンド実行の実装
```

### 3.3 設定ファイル形式

テスト設定ファイル（`test_config.json`）は以下の形式で記述します：

```json
{
  "test_cases": {
    "CC-001": true, // 基本生成テスト
    "CC-002": true, // 複数回生成テスト
    "CC-003": true, // パスワード変更テスト
    "CC-004": true, // 検証オプションテスト
    "CS-001": true, // パーティションマップキー長テスト
    "CS-002": true, // パーティション分離検証
    "CS-003": false, // 異常入力検証（無効化例）
    "CS-004": true // パーティションマップキー強度検証
  },
  "analytics": {
    "key_length": true, // キー長分析
    "key_randomness": true, // キーのランダム性分析
    "key_uniqueness": true, // キーの一意性分析
    "partition_overlap": true, // パーティション重複分析
    "share_ratio": true, // シェア比率分析
    "share_distribution": true, // シェア分布分析
    "execution_time": false, // 実行時間分析（無効化例）
    "memory_usage": false // メモリ使用量分析（無効化例）
  },
  "reporting": {
    "include_raw_data": false,
    "generate_charts": true
  }
}
```

### 3.4 テストケースファイル構造

各テストケースは以下の構造で実装します：

```python
# test_cases/crypto_storage_creation/test_cc_001_basic_creation.py

from test_cases.base_test import BaseTest
from utils.cli_runner import run_cli_command

class TestBasicCreation(BaseTest):
    """基本生成テスト（CC-001）

    基本パラメータで暗号書庫を生成し、出力を検証する。
    """

    def __init__(self):
        super().__init__()
        self.test_id = "CC-001"
        self.test_name = "基本生成テスト"

    def run(self):
        """テストケースを実行する"""
        # CLIコマンド実行
        exit_code, stdout, stderr = run_cli_command(
            'create_storage.py',
            {
                '--output': 'test_storage.bin',
                '--password-a': self.get_password('A'),
                '--password-b': self.get_password('B')
            }
        )

        # 結果検証（簡略化例）
        self.results['exit_code'] = exit_code
        self.results['success'] = exit_code == 0
        self.results['storage_file_created'] = self.check_file_exists('test_storage.bin')

        # 出力からパーティションマップキーを抽出
        self.results['partition_map_key_a'] = self.extract_map_key(stdout, 'A')
        self.results['partition_map_key_b'] = self.extract_map_key(stdout, 'B')

        return self.results
```

### 3.5 分析ファイル構造

各分析機能は以下の構造で実装します：

```python
# analysis/key_length_analyzer.py

class KeyLengthAnalyzer:
    """パーティションマップキー長分析

    生成されたパーティションマップキーの長さを分析し、十分な長さであるかを検証する。
    """

    def __init__(self):
        self.name = "key_length"
        self.description = "パーティションマップキー長分析"

    def analyze(self, test_results):
        """
        パーティションマップキーの長さを分析する

        Args:
            test_results: テスト結果データ

        Returns:
            analysis_results: 分析結果
        """
        analysis_results = {
            'name': self.name,
            'description': self.description,
            'keys_analyzed': [],
            'length_statistics': {},
            'pass': True  # デフォルトは合格
        }

        # 各テスト結果からパーティションマップキーを取得して分析
        for test_id, result in test_results.items():
            if 'partition_map_key_a' in result and 'partition_map_key_b' in result:
                key_a = result['partition_map_key_a']
                key_b = result['partition_map_key_b']

                # キー長の検証
                key_a_length = len(key_a)
                key_b_length = len(key_b)

                analysis_results['keys_analyzed'].append({
                    'test_id': test_id,
                    'key_a_length': key_a_length,
                    'key_b_length': key_b_length
                })

                # 最小期待長（例として）
                min_expected_length = 500  # 最小期待長は実際のシステム値に基づいて設定

                if key_a_length < min_expected_length or key_b_length < min_expected_length:
                    analysis_results['pass'] = False

        # 統計情報の計算
        if analysis_results['keys_analyzed']:
            lengths_a = [k['key_a_length'] for k in analysis_results['keys_analyzed']]
            lengths_b = [k['key_b_length'] for k in analysis_results['keys_analyzed']]

            analysis_results['length_statistics'] = {
                'key_a': {
                    'min': min(lengths_a),
                    'max': max(lengths_a),
                    'avg': sum(lengths_a) / len(lengths_a)
                },
                'key_b': {
                    'min': min(lengths_b),
                    'max': max(lengths_b),
                    'avg': sum(lengths_b) / len(lengths_b)
                }
            }

        return analysis_results
```

### 3.6 テストレポート生成

テスト結果は`test_report_template.md`の形式に従って生成されます。レポート生成プロセスの流れ：

1. テスト結果データの収集（各テストケースから独立して）
2. 分析結果データの収集（各分析機能から独立して）
3. テンプレートの読み込み
4. テンプレート内のプレースホルダーにデータを挿入
5. 生成されたレポートを保存

## 4. テストケース設計

### 4.1 暗号書庫生成テスト（createCryptoStorage）

#### 4.1.1 基本機能テスト

| テスト ID | テスト名             | 内容                                 | 期待結果                                                             |
| --------- | -------------------- | ------------------------------------ | -------------------------------------------------------------------- |
| CC-001    | 基本生成テスト       | 基本パラメータで暗号書庫を生成       | 暗号書庫ファイルが生成され、A/B パーティションマップキーが出力される |
| CC-002    | 複数回生成テスト     | 同じパラメータで 10 回暗号書庫を生成 | 各実行で異なるパーティションマップキーが生成される                   |
| CC-003    | パスワード変更テスト | 異なるパスワードで暗号書庫を生成     | 異なるパーティションマップキーが生成される                           |
| CC-004    | 検証オプションテスト | `--verify`オプション付きで実行       | パーティション分離検証が成功する                                     |

#### 4.1.2 セキュリティテスト

| テスト ID | テスト名                         | 内容                                 | 期待結果                                           |
| --------- | -------------------------------- | ------------------------------------ | -------------------------------------------------- |
| CS-001    | パーティションマップキー長テスト | パーティションマップキーの長さを検証 | キー長がシステム値に比例して十分な長さになっている |
| CS-002    | パーティション分離検証           | A/B パーティションの重複を検証       | A/B パーティション間に重複がない                   |
| CS-003    | 異常入力検証                     | 無効なパスワード、パスなどで実行     | 適切なエラーメッセージが表示される                 |
| CS-004    | パーティションマップキー強度検証 | マップキーの統計的特性を分析         | 暗号学的に十分なランダム性がある                   |

## 5. テストデータ分析

テスト結果データは以下の分析を行います（設定ファイルで個別に有効/無効化可能）：

### 5.1 パーティションマップキー分析

分析ファイル:

- `key_length_analyzer.py` - キー長の検証（適切なな長さであるか）
- `key_randomness_analyzer.py` - キーの統計的ランダム性（ビット分布）
- `key_uniqueness_analyzer.py` - 複数回生成時の一意性

### 5.2 パーティション分布分析

分析ファイル:

- `partition_overlap_analyzer.py` - A/B パーティション間の重複チェック
- `share_ratio_analyzer.py` - ACTIVE_SHARES と GARBAGE_SHARES の比率検証
- `share_distribution_analyzer.py` - シェア分布の均一性検証

### 5.3 パフォーマンス分析

分析ファイル:

- `execution_time_analyzer.py` - 実行時間測定
- `memory_usage_analyzer.py` - メモリ使用量測定（可能な場合）

## 6. レポート生成詳細

### 6.1 レポートデータマッピング

`test_report_template.md`のプレースホルダーとテスト結果データのマッピング：

| プレースホルダー                 | データソース                      | 説明                                               |
| -------------------------------- | --------------------------------- | -------------------------------------------------- |
| `{execution_datetime}`           | 現在時刻                          | テスト実行日時                                     |
| `{パーティションサイズ値}`       | ShamirConstants.PARTITION_SIZE    | システム定数からの値                               |
| `{アクティブシェア数}`           | ShamirConstants.ACTIVE_SHARES     | システム定数からの値                               |
| `{ガベージシェア数}`             | ShamirConstants.GARBAGE_SHARES    | システム定数からの値                               |
| `{未割当シェア数}`               | ShamirConstants.UNASSIGNED_SHARES | システム定数からの値                               |
| `{チャンクサイズ (バイト)}`      | ShamirConstants.CHUNK_SIZE        | システム定数からの値                               |
| `{暗号化ファイル名}`             | CLI の出力から抽出                | 各テスト実行で生成された暗号書庫ファイル名         |
| `{A 用パーティションマップキー}` | CLI の出力から抽出                | A 領域のパーティションマップキー                   |
| `{B 用パーティションマップキー}` | CLI の出力から抽出                | B 領域のパーティションマップキー                   |
| `{A 用パスワード}`               | テスト入力から                    | A 領域用に使用したパスワード（ハッシュ表示を検討） |
| `{B 用パスワード}`               | テスト入力から                    | B 領域用に使用したパスワード（ハッシュ表示を検討） |

### 6.2 レポート生成プロセス

1. テスト結果データを構造化されたフォーマットで収集
2. テンプレートファイルを読み込み
3. 正規表現を使用してプレースホルダーを特定
4. 各プレースホルダーをテストデータで置換
5. マークダウン表を動的に生成（テスト成功/失敗の ✅/❌ など）
6. 最終レポートを`test_report/test_report_{YYYYMMDD}_{HHMMSS}.md`として保存

## 7. テストの拡張性

将来的なテスト拡張に備えて、以下の設計を取り入れています：

### 7.1 モジュール式テスト構造

- 各テストケースは独立したファイルとして実装
- すべてのテストケースは共通の基底クラスを継承
- 新しいテストケースの追加は、新しいファイルを追加するだけで可能

### 7.2 共通ユーティリティ

- CLI 実行、レポート生成などの共通機能は再利用可能なユーティリティとして実装
- 新しいテストケースでも同じユーティリティを使用可能

### 7.3 設定ファイルによる制御

- テストケースは設定ファイルで個別に有効/無効化可能
- 分析処理も設定ファイルで個別に有効/無効化可能
- 新しいテストケースや分析処理を追加した場合も、設定ファイルに項目を追加するだけで制御可能

## 8. 実装ステップ

### 8.1 初期実装（現在のフェーズ）

1. ディレクトリ構造の作成
2. 基本的なユーティリティの実装（cli_runner.py, config_loader.py など）
3. テスト基底クラスの実装（base_test.py）
4. 設定ファイル形式の定義と読み込み機能の実装
5. 基本的なテストケースの実装（CC-001 など）
6. 基本的な分析機能の実装（key_length_analyzer.py など）
7. レポート生成機能の実装

### 8.2 将来の拡張（次フェーズ）

1. 残りのテストケースの追加
2. 暗号書庫更新テストケースの追加
3. 暗号書庫読取テストケースの追加
4. 高度な分析機能の追加

## 9. 結論

この設計により、バックドアやバイパスなしで実際の CLI を使用した信頼性の高いテストが可能になります。1 機能 1 ファイルの原則に従い、各テストケースと各分析機能は独立したファイルとして実装されます。これにより、コードの可読性、保守性、拡張性が向上します。テストケースや分析処理は設定ファイルで個別に有効/無効化でき、柔軟な運用が可能です。テスト結果は明確なフォーマットで報告され、システムの暗号学的安全性と機能的正確性を確認できます。

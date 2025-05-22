# シャミア秘密分散法による複数平文復号システム

シャミア秘密分散法を用いて、複数の独立した平文を同一暗号書庫に格納し、各々を異なる権限で復号できるシステムの実装です。

## 暗号書庫生成機能

暗号書庫生成機能（`createCryptoStorage`）は、シャミア秘密分散法による複数平文復号システムの基盤となる暗号書庫を生成し、A/B 両領域用のパーティションマップキーを作成します。

## インストール方法

必要なパッケージをインストールします：

```bash
pip install -r requirements.txt
```

## 使用方法

### コマンドラインから実行

```bash
python -m method_13_shamir_multi_plaintext_system.cli.create_storage [オプション]
```

#### オプション

- `-o, --output-dir` - 出力ディレクトリを指定（デフォルト: ./output）
- `-a, --a-password` - A 領域用パスワードを指定
- `-b, --b-password` - B 領域用パスワードを指定
- `-g, --generate-passwords` - 安全なランダムパスワードを自動生成
- `-p, --partition-size` - パーティションサイズを指定
- `-u, --unassigned-shares` - 未割当シェア数を指定
- `-s, --active-shares` - アクティブシェア数を指定
- `-v, --verify` - 生成後にパーティションマップキーを検証

### 例

ランダムパスワードを生成して暗号書庫を作成し、検証を行う：

```bash
python -m method_13_shamir_multi_plaintext_system.cli.create_storage -g -v
```

特定のパスワードを指定して小さなサイズの暗号書庫を作成：

```bash
python -m method_13_shamir_multi_plaintext_system.cli.create_storage -a "a_password" -b "b_password" -p 100 -u 100 -s 50
```

## API として使用

```python
from method_13_shamir_multi_plaintext_system.shamir.crypto_storage_creation import create_crypto_storage

# 暗号書庫の生成
storage_file, a_partition_map_key, b_partition_map_key = create_crypto_storage(
    a_password="a_password",
    b_password="b_password",
    output_dir="./output",
    parameters={
        'PARTITION_SIZE': 10,
        'ACTIVE_SHARES': 5,
        'UNASSIGNED_SHARES': 10,
        'SHARE_ID_SPACE': 30,
    }
)

print(f"暗号書庫ファイル: {storage_file}")
print(f"A領域用パーティションマップキー: {a_partition_map_key}")
print(f"B領域用パーティションマップキー: {b_partition_map_key}")
```

## 技術的概要

### 暗号書庫生成のフロー

1. シェア ID 空間の分割

   - 全シェア ID 空間を暗号学的に安全なシャッフルを用いて 3 区画に分割（A 領域、B 領域、未割当領域）
   - 各区画が互いに重複しないことを検証

2. ガベージシェアの生成

   - 全シェア空間に統計的に区別不可能なガベージシェアを配置

3. パーティションマップキーの生成
   - A/B 各領域の第 1 段階 MAP を AES-GCM で暗号化し、パーティションマップキーを生成

### セキュリティ特性

- **完全性**: パーティションマップキーを復号した際の配列の数が PARTITION_SIZE と完全に一致
- **分離性**: A 領域と B 領域の配列が互いに重複せず完全に分離
- **予測不可能性**: 複数回の実行で生成される暗号書庫がそれぞれ異なる配列を持つ
- **統計的区別不可能性**: ガベージシェアと有効シェアが統計的に区別できない

## ファイル構成

- `shamir/crypto_storage_creation.py` - 暗号書庫生成機能の中核実装
- `cli/create_storage.py` - コマンドラインインターフェース
- `tests/test_crypto_storage_creation.py` - 単体テスト

## 概要

このシステムは、シャミア秘密分散法を応用して単一の暗号化ファイルから異なるパスワードを使用して異なる平文（JSON 文書）を復号可能にするものです。「パーティションマップキーによる MAP 生成とパスワードによるマップ生成」という多段 MAP 方式を核心としています。

本システムの設計はケルクホフの原理に厳格に従い、アルゴリズムが完全に公開されてもパスワード（鍵）が秘匿されている限りセキュリティが保たれます。また、サイドチャネル攻撃に対する耐性を持つ直線的処理を採用しています。

## 特徴

- **多段 MAP 方式**: パーティションマップキーとパスワードを組み合わせた 2 段階のマッピング方式により、単一ファイルから異なる文書を復号可能
- **統計的区別不可能性**: 暗号化ファイル内のシェアが統計的に区別できず、外部観察者がどのシェアがどの文書に属するか識別できない
- **サイドチャネル攻撃耐性**: 条件分岐を避けた直線的処理により、タイミング攻撃などへの耐性を確保
- **原子的更新**: WAL ログ方式とファイルロック機構による安全なファイル更新

## インストール

### 必要条件

- Python 3.7 以上
- gmpy2
- cryptography

### パッケージのインストール

```bash
# 必要なパッケージをインストール
pip install -r requirements.txt
```

## 使い方

### システムの初期化

```bash
python -m shamir init --output system_info.json
```

### JSON 文書の暗号化

```bash
python -m shamir encrypt \
  --input document_a.json \
  --output encrypted.json \
  --password "password_for_a" \
  --partition-key "your_partition_key"
```

### 暗号化ファイルの復号

```bash
python -m shamir decrypt \
  --input encrypted.json \
  --output decrypted.json \
  --password "password_for_a" \
  --partition-key "your_partition_key"
```

### 暗号化ファイルの更新

```bash
python -m shamir update \
  --encrypted-input encrypted.json \
  --json-input new_document.json \
  --output updated_encrypted.json \
  --password "password_for_b" \
  --partition-key "your_partition_key"
```

### セキュリティ自己診断

```bash
python -m shamir security-test --output security_report.json
```

### 初期化済み暗号化ファイルの生成

パーティション全体をガベージシェアで埋めた初期化済み暗号化ファイルを生成することで、統計的区別不可能性を確保できます。このファイルは設計書の要件に完全準拠した形式（V3 形式）で作成されます。

```bash
# Pythonモジュールを使用する方法
python -m shamir init --generate-empty-file --output-dir ./output

# スタンドアロンスクリプトを使用する方法（依存関係の問題を回避）
python generate_standalone.py --chunks 10 --output-dir ./output
```

初期化済み暗号化ファイルの特徴：

- 全てのシェア ID がガベージシェアで埋められている
- 統計的区別不可能性が確保されている（有効なシェア、無効なシェアを区別できない）
- ソルト値のみの最小限のメタデータ
- 常に新たな UUID を持つファイル名で生成される

## 使用例

### 複数文書の暗号化と復号

1. システムを初期化してパーティションマップキーを取得

```bash
python -m shamir init --output keys.json
```

2. A ユーザー用の JSON を暗号化

```bash
python -m shamir encrypt \
  --input userA_data.json \
  --output encrypted.json \
  --password "passwordA" \
  --partition-key "$(jq -r .partition_a_key keys.json)"
```

3. B ユーザー用の JSON を暗号化（既存ファイルの更新として）

```bash
python -m shamir update \
  --encrypted-input encrypted.json \
  --json-input userB_data.json \
  --password "passwordB" \
  --partition-key "$(jq -r .partition_b_key keys.json)"
```

4. A ユーザーとして復号

```bash
python -m shamir decrypt \
  --input encrypted.json \
  --password "passwordA" \
  --partition-key "$(jq -r .partition_a_key keys.json)"
```

5. B ユーザーとして復号

```bash
python -m shamir decrypt \
  --input encrypted.json \
  --password "passwordB" \
  --partition-key "$(jq -r .partition_b_key keys.json)"
```

## セキュリティに関する注意事項

- パーティションマップキーは重要な秘密情報です。安全に保管してください。
- パスワードは十分に強力なものを使用してください。
- 本システムは暗号化されていても、認証を提供するものではありません。
- ファイルシステムのバックアップを定期的に行い、データ損失を防ぐことを推奨します。

## アーキテクチャ

システムは以下のコンポーネントで構成されています：

- **core.py**: シャミア秘密分散法の中核機能を実装
- **partition.py**: パーティション空間管理機能を実装
- **crypto.py**: 暗号化と復号の機能を実装
- **update.py**: 更新処理を実装
- **tests.py**: セキュリティテストと自己診断ツールを実装
- **app.py**: メインアプリケーションを実装

## ライセンス

MIT

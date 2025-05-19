# シャミア秘密分散法による複数平文復号システム - 使用ガイド

## 1. 概要

このシステムは、シャミア秘密分散法を応用して単一の暗号化ファイルから異なるパスワードを使用して異なる平文（JSON 文書）を復号可能にします。「パーティションマップキーによる MAP 生成とパスワードによるマップ生成」という多段 MAP 方式を核心としています。

## 2. インストール方法

### 必要条件

- Python 3.7 以上
- gmpy2 ライブラリ
- cryptography ライブラリ

### インストール手順

```bash
# リポジトリをクローン
git clone <リポジトリURL>
cd shamir-secret-sharing-demo/method_13_shamir_multi_plaintext_system

# 依存パッケージをインストール
pip install -r requirements.txt

# または直接インストール
pip install gmpy2 cryptography
```

### セットアップの確認

```bash
# テストを実行して動作確認
cd tests
python -m unittest test_basic.py
```

## 3. 基本的な使い方

### システムの初期化

最初に、システムを初期化してパーティションマップキーを生成します。

```bash
python -m shamir init --output system_info.json
```

これにより、A ユーザーと B ユーザー用のパーティションマップキーが生成され、`system_info.json` に保存されます。
**注意**: このファイルには秘密のパーティションマップキーが含まれるため、安全に保管してください。

### JSON ファイルの暗号化（A ユーザー用）

```bash
python -m shamir encrypt \
  --input document_a.json \
  --output encrypted.json \
  --password "password_for_a" \
  --partition-key "your_partition_key"
```

### JSON ファイルの暗号化（B ユーザー用）

既存の暗号化ファイルを更新することで、B ユーザー用の文書を追加します。

```bash
python -m shamir update \
  --encrypted-input encrypted.json \
  --json-input document_b.json \
  --output encrypted.json \
  --password "password_for_b" \
  --partition-key "your_partition_key"
```

### 暗号化ファイルの復号（A ユーザー）

```bash
python -m shamir decrypt \
  --input encrypted.json \
  --output decrypted_a.json \
  --password "password_for_a" \
  --partition-key "your_partition_key"
```

### 暗号化ファイルの復号（B ユーザー）

```bash
python -m shamir decrypt \
  --input encrypted.json \
  --output decrypted_b.json \
  --password "password_for_b" \
  --partition-key "your_partition_key"
```

## 4. サンプルプログラム

システムの使い方を示すサンプルプログラムが `tests/example.py` に含まれています。

```bash
cd method_13_shamir_multi_plaintext_system
python -m tests.example
```

このサンプルは以下の処理を実行します：

1. システムの初期化
2. A ユーザー用の文書を暗号化
3. B ユーザー用の文書を同じファイルに追加
4. A ユーザーとして復号
5. B ユーザーとして復号
6. 異なるパスワードで復号を試みる（失敗を確認）
7. セキュリティ自己診断の実行

## 5. 高度な機能

### セキュリティ自己診断

システムのセキュリティ特性を診断します。

```bash
python -m shamir security-test --output security_report.json
```

この診断では以下の項目が検証されます：

- パーティション空間の統計的区別不可能性
- シェア値の均一性
- タイミング攻撃耐性
- パーティション間の統計的独立性

### 更新前の検証

文書更新前に検証を行い、問題がないか確認します。

```bash
python -m shamir update \
  --encrypted-input encrypted.json \
  --json-input new_document.json \
  --password "password_for_a" \
  --partition-key "your_partition_key" \
  --dry-run
```

## 6. セキュリティに関する注意事項

- パーティションマップキーは重要な秘密情報です。安全に保管してください。
- パスワードは十分に強力なものを使用してください。
- 同一パスワードを複数のユーザーで共有しないでください。
- 本システムは暗号化されていても、認証を提供するものではありません。
- ファイルシステムのバックアップを定期的に行い、データ損失を防ぐことを推奨します。

## 7. エラーの対処方法

### 「復号化に失敗しました」エラー

以下を確認してください：

- パスワードが正しいか
- パーティションマップキーが正しいか
- 暗号化ファイルが破損していないか

### 「更新に失敗しました」エラー

更新処理では、既存ファイルの復号に成功してから新しい文書を暗号化する必要があります。以下を確認してください：

- パスワードが正しいか
- パーティションマップキーが正しいか
- ファイルへの書き込み権限があるか

## 8. ライセンス

このソフトウェアは MIT ライセンスの下で提供されています。

# シャミア秘密分散法による複数平文復号システム

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

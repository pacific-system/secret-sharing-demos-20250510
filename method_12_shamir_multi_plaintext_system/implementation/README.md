# シャミア秘密分散法による複数平文復号システム

このシステムは、シャミア秘密分散法を使用して複数の JSON 文書を単一の暗号化ファイルに格納し、異なるパスワードと異なるシェア ID セットを使用して、それぞれ異なる文書を復号できるようにします。

## システム概要

- **核心技術**: 「シェア ID による可能性の限定とパスワードによるマップ生成」という多段 MAP 方式
- **セキュリティモデル**: ケルクホフの原理に基づき、アルゴリズムが公開されてもパスワードが秘匿されていれば安全

### 主な特徴

1. **統計的区別不可能性**: 異なる文書のシェアや未割当領域のシェアが統計的に区別できない
2. **直線的処理**: 復号処理中に条件分岐が含まれず、タイミング攻撃に耐性がある
3. **安全な更新機能**: 既存の暗号化ファイルの特定文書部分のみを安全に更新可能
4. **多段 MAP 方式**: シェア ID 空間を効率的に利用するための多段階マッピング機構

## インストール方法

```bash
# リポジトリをクローン
git clone [リポジトリURL]
cd method_12_shamir_multi_plaintext_system/implementation

# 依存パッケージをインストール
pip install -r requirements.txt

# パッケージをインストール
pip install -e .
```

## 基本的な使い方

### 1. シェア ID の生成

```bash
# 100個のシェアIDを生成（A:B:未割当の比率は35:35:30）
shamir-multi-crypt generate --output shares.json
```

### 2. 暗号化

```bash
# A文書とB文書を暗号化
shamir-multi-crypt init --file-a doc_a.json --file-b doc_b.json --shares shares.json --output encrypted.json
```

### 3. 復号

```bash
# A文書を復号
shamir-multi-crypt decrypt --input encrypted.json --shares shares_a.json --output decrypted_a.json
```

### 4. 更新

```bash
# A文書を更新
shamir-multi-crypt update --input encrypted.json --file new_doc_a.json --shares shares_a.json
```

## コマンド詳細

- `generate`: シェア ID セットを生成
- `init`: 複数の JSON 文書を暗号化して単一の暗号化ファイルを作成
- `decrypt`: シェア ID セットとパスワードを使用して文書を復号
- `update`: 暗号化ファイル内の特定の文書を更新

各コマンドの詳細なオプションは `shamir-multi-crypt <コマンド> --help` で確認できます。

## セキュリティ上の注意

- パスワードは十分に強力なものを使用してください
- シェア ID セットは安全に管理してください。失うとデータを復元できなくなります
- 暗号化ファイルのバックアップを定期的に作成することをお勧めします

## ライセンス

MIT License

## 貢献

Issues, Pull Requests を歓迎します。

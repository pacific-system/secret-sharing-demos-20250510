# 暗号学的ハニーポット方式 🍯 実装【子 Issue #1】：ディレクトリ構造と基本ファイルの作成

お兄様！最初のステップとして、暗号学的ハニーポット方式の基盤を整えましょう！✨

## 📋 タスク概要

暗号学的ハニーポット方式の実装に必要なディレクトリ構造を作成し、基本ファイルを準備します。これにより、後続のタスクがスムーズに進行できるようになります。

## 🗂️ 作成するディレクトリ構造

以下の構造を作成してください：

```
/
├── method_7_honeypot/                   # 暗号学的ハニーポット方式のメインディレクトリ
│   ├── __init__.py                      # Pythonパッケージ化
│   └── tests/                           # テストディレクトリ
│       └── __init__.py                  # テストパッケージ化
└── common/                              # 既存ディレクトリ
    └── true-false-text/                 # テストファイル用ディレクトリ（必要に応じて作成）
```

## 💻 実装手順

### 1. ディレクトリ構造の作成

```bash
# 暗号学的ハニーポット方式のディレクトリ作成
mkdir -p method_7_honeypot/tests

# 必要なinitファイルを作成
touch method_7_honeypot/__init__.py
touch method_7_honeypot/tests/__init__.py

# テストファイル用ディレクトリ確認・作成
mkdir -p common/true-false-text
```

### 2. 基本ファイルの作成

以下のファイルを空ファイルとして作成してください。後続のタスクで実装します。

```bash
# 主要ファイル
touch method_7_honeypot/encrypt.py
touch method_7_honeypot/decrypt.py
touch method_7_honeypot/honeypot_crypto.py
touch method_7_honeypot/trapdoor.py
touch method_7_honeypot/key_verification.py
touch method_7_honeypot/honeypot_capsule.py
touch method_7_honeypot/deception.py

# テストファイル
touch method_7_honeypot/tests/test_trapdoor.py
touch method_7_honeypot/tests/test_key_verification.py
touch method_7_honeypot/tests/test_encrypt_decrypt.py
touch method_7_honeypot/tests/test_tamper_resistance.py
```

### 3. テストデータの確認・作成

`common/true-false-text/` ディレクトリに、テスト用のファイルが存在することを確認します。ない場合は作成します。

```bash
# 正規ファイルの作成（存在しない場合）
if [ ! -f common/true-false-text/true.text ]; then
    echo "これは正規のファイルです。正しい鍵で復号されたことを示します。" > common/true-false-text/true.text
fi

# 非正規ファイルの作成（存在しない場合）
if [ ! -f common/true-false-text/false.text ]; then
    echo "これは非正規のファイルです。不正な鍵で復号されたことを示します。" > common/true-false-text/false.text
fi
```

### 4. 基本設定ファイルの作成

プロジェクト管理のための基本設定ファイルを作成します。

`method_7_honeypot/config.py` ファイルを作成し、以下の内容を記述してください：

```python
"""
暗号学的ハニーポット方式の設定ファイル
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 暗号化パラメータ
KEY_SIZE_BITS = 2048  # RSAトラップドア関数の鍵サイズ
SYMMETRIC_KEY_SIZE = 32  # 対称暗号の鍵サイズ（AES-256用）
IV_SIZE = 16  # 初期化ベクトルサイズ

# 鍵導出パラメータ
KDF_ITERATIONS = 10000  # 鍵導出関数の反復回数
SALT_SIZE = 16  # ソルトサイズ

# ハニーポットパラメータ
TOKEN_SIZE = 32  # ハニートークンサイズ
CAPSULE_VERSION = 1  # カプセル形式バージョン

# 出力ファイル形式
OUTPUT_FORMAT = "honeypot"
OUTPUT_EXTENSION = ".hpot"

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False
```

### 5. README.md の作成

`method_7_honeypot/README.md` ファイルを作成し、以下の内容を記述してください：

````markdown
# 暗号学的ハニーポット方式 🍯

このモジュールは、「囮」の原理を用いて同一の暗号文から異なる平文を復元できる機能を実装します。

## 使い方

### 暗号化

```bash
python -m method_7_honeypot.encrypt --true-file path/to/true.text --false-file path/to/false.text --output output.hpot
```

### 復号

```bash
python -m method_7_honeypot.decrypt output.hpot --key your_key --output decrypted.txt
```

## ハニーポット機能の特徴

この方式は、トラップドア関数を用いて鍵の真偽を判定し、判定結果に応じて異なる経路で復号を行います。
ソースコード解析やスクリプト改変に対しても耐性を持ち、攻撃者は真の復号結果を判別できません。

## 詳細情報

詳細は各モジュールのドキュメントを参照してください。
````

## ✅ 完了条件

- [ ] すべてのディレクトリが適切な場所に作成されている
- [ ] すべての基本ファイルが作成されている
- [ ] テストデータファイルが存在し、適切な内容が記述されている
- [ ] config.py ファイルが作成され、適切な設定が記述されている
- [ ] README.md ファイルが作成され、適切な情報が記述されている
- [ ] 各ファイルの権限が適切に設定されている（実行可能ファイルは 755、それ以外は 644）

## ⏰ 想定実装時間

約 2 時間

## 💬 備考

- このステップは後続タスクの基盤となる重要な作業です
- ディレクトリ構造やファイル名は厳密に守ってください
- 設定ファイルのパラメータ値は、セキュリティと実行速度のバランスを考慮して設定されています
- 本番環境では、KEY_SIZE_BITS や KDF_ITERATIONS などのセキュリティパラメータをさらに強化することを検討してください

疑問点や提案があればコメントしてくださいね！パシ子とレオくんが全力でサポートします！💕

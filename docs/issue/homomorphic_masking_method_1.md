# 準同型暗号マスキング方式 🎭 実装【子 Issue #1】：ディレクトリ構造と基本ファイルの作成

お兄様！準同型暗号マスキング方式の実装を始めるために、まずはプロジェクトの土台を整えましょう！✨

## 📋 タスク概要

準同型暗号マスキング方式の実装に必要なディレクトリ構造を作成し、基本ファイルを準備します。これにより、後続のタスクがスムーズに進行できるようになります。

## 🗂️ 作成するディレクトリ構造

以下の構造を作成してください：

```
/
├── method_8_homomorphic/                 # 準同型暗号マスキング方式のメインディレクトリ
│   ├── __init__.py                       # Pythonパッケージ化
│   └── tests/                            # テストディレクトリ
│       └── __init__.py                   # テストパッケージ化
└── common/                               # 既存ディレクトリ
    └── true-false-text/                  # テストファイル用ディレクトリ（必要に応じて作成）
```

## 💻 実装手順

### 1. ディレクトリ構造の作成

```bash
# 準同型暗号マスキング方式のディレクトリ作成
mkdir -p method_8_homomorphic/tests

# 必要なinitファイルを作成
touch method_8_homomorphic/__init__.py
touch method_8_homomorphic/tests/__init__.py

# テストファイル用ディレクトリ確認・作成
mkdir -p common/true-false-text
```

### 2. 基本ファイルの作成

以下のファイルを空ファイルとして作成してください。後続のタスクで実装します。

```bash
# 主要ファイル
touch method_8_homomorphic/encrypt.py
touch method_8_homomorphic/decrypt.py
touch method_8_homomorphic/homomorphic.py
touch method_8_homomorphic/crypto_mask.py
touch method_8_homomorphic/key_analyzer.py
touch method_8_homomorphic/indistinguishable.py

# テストファイル
touch method_8_homomorphic/tests/test_homomorphic.py
touch method_8_homomorphic/tests/test_crypto_mask.py
touch method_8_homomorphic/tests/test_encrypt_decrypt.py
touch method_8_homomorphic/tests/test_indistinguishability.py
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

`method_8_homomorphic/config.py` ファイルを作成し、以下の内容を記述してください：

```python
"""
準同型暗号マスキング方式の設定ファイル
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 準同型暗号パラメータ
KEY_SIZE_BITS = 1024  # 鍵サイズ（小さめの値でデモ用）
SECURITY_PARAMETER = 80  # セキュリティパラメータ

# 鍵導出パラメータ
KDF_ITERATIONS = 1000  # 鍵導出関数の反復回数
SALT_SIZE = 16         # ソルトサイズ

# 出力ファイル形式
OUTPUT_FORMAT = "homomorphic"
OUTPUT_EXTENSION = ".henc"

# マスク関数パラメータ
MASK_SEED_SIZE = 32     # マスク生成シードサイズ
NUM_MASK_FUNCTIONS = 4  # マスク関数の数

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False
```

### 5. README.md の作成

`method_8_homomorphic/README.md` ファイルを作成し、以下の内容を記述してください：

````markdown
# 準同型暗号マスキング方式 🎭

このモジュールは、準同型暗号の特性を利用して同一の暗号文から異なる平文を復元できる機能を実装します。

## 使い方

### 暗号化

```bash
python -m method_8_homomorphic.encrypt --true-file path/to/true.text --false-file path/to/false.text --output output.henc
```
````

### 復号

```bash
python -m method_8_homomorphic.decrypt output.henc --key your_key --output decrypted.txt
```

## 準同型暗号の特徴

準同型暗号は暗号文のまま計算ができる特殊な暗号方式です。
この特性を利用して、暗号文に対して鍵に応じた異なるマスクを適用し、復号時に異なる結果を得ることができます。

## 詳細情報

詳細は各モジュールのドキュメントを参照してください。

```

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

- このステップで作成するのは空のファイルが中心ですが、後続のタスクでそれぞれ実装していきます
- ディレクトリ構造やファイル名は厳密に守ってください
- 各種パラメータ値は準同型暗号の特性を考慮して設定していますが、デモ用のため小さな値を使用しています
- 実際のアプリケーションでは、より大きな鍵サイズや高いセキュリティパラメータを使用すべきです

疑問点や提案があればコメントしてくださいね！パシ子とレオくんがお手伝いします！💕
```

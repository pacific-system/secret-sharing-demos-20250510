# ラビット暗号化方式 🐰 実装【子 Issue #1】：ディレクトリ構造と基本ファイルの作成

お兄様！最初のステップとして、プロジェクトの基盤を整えましょう！✨

## 📋 タスク概要

ラビット暗号化方式の実装に必要なディレクトリ構造を作成し、基本ファイルを準備します。これにより、後続のタスクがスムーズに進行できるようになります。

## 🗂️ 作成するディレクトリ構造

以下の構造を作成してください：

```
/
├── method_6_rabbit/                  # ラビット暗号化方式のメインディレクトリ
│   ├── __init__.py                   # Pythonパッケージ化
│   └── tests/                        # テストディレクトリ
│       └── __init__.py               # テストパッケージ化
└── common/                           # 既存ディレクトリ
    └── true-false-text/              # テストファイル用ディレクトリ（必要に応じて作成）
```

## 💻 実装手順

### 1. ディレクトリ構造の作成

```bash
# ラビット暗号化方式のディレクトリ作成
mkdir -p method_6_rabbit/tests

# 必要なinitファイルを作成
touch method_6_rabbit/__init__.py
touch method_6_rabbit/tests/__init__.py

# テストファイル用ディレクトリ確認・作成
mkdir -p common/true-false-text
```

### 2. 基本ファイルの作成

以下のファイルを空ファイルとして作成してください。後続のタスクで実装します。

```bash
# 主要ファイル
touch method_6_rabbit/encrypt.py
touch method_6_rabbit/decrypt.py
touch method_6_rabbit/rabbit_stream.py
touch method_6_rabbit/multipath_decrypt.py
touch method_6_rabbit/stream_selector.py

# テストファイル
touch method_6_rabbit/tests/test_encrypt.py
touch method_6_rabbit/tests/test_decrypt.py
touch method_6_rabbit/tests/test_indistinguishability.py
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

`method_6_rabbit/config.py` ファイルを作成し、以下の内容を記述してください：

```python
"""
ラビット暗号化方式の設定ファイル
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 暗号化パラメータ
KEY_SIZE_BYTES = 16  # 128ビット鍵
IV_SIZE_BYTES = 8    # 64ビットIV
BLOCK_SIZE = 16      # 処理ブロックサイズ

# 鍵導出パラメータ
KDF_ITERATIONS = 1000  # 鍵導出関数の反復回数
SALT_SIZE = 16         # ソルトサイズ

# 出力ファイル形式
OUTPUT_FORMAT = "rabbit"
OUTPUT_EXTENSION = ".enc"

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False
```

## ✅ 完了条件

- [ ] すべてのディレクトリが適切な場所に作成されている
- [ ] すべての基本ファイルが作成されている
- [ ] テストデータファイルが存在し、適切な内容が記述されている
- [ ] config.py ファイルが作成され、適切な設定が記述されている
- [ ] 各ファイルの権限が適切に設定されている

## ⏰ 想定実装時間

約 2 時間

## 💬 備考

- このステップが正しく完了していることが、後続タスクの円滑な実装の鍵となります
- ディレクトリ構造やファイル名は厳密に守ってください
- ファイルパーミッションは適切に設定してください（実行可能ファイルは 755、それ以外は 644）
- 疑問点や提案があればコメントしてくださいね！💕

# CLI インターフェース実装ガイド

## CLI の目的

この CLI インターフェースは、シャミア秘密分散法による複数平文復号システムの 3 つの主要機能（暗号化・復号・更新）を利用しやすくするためのコマンドラインツールです。セキュリティを確保しつつ、ユーザーフレンドリーな操作性を提供します。

## コマンド設計

### 1. ヘルプとサブコマンド構造

ツールは以下のサブコマンドを持ちます：

```
shamir-multi-crypt [グローバルオプション] <サブコマンド> [サブコマンドオプション]

サブコマンド:
  - init      : 新規暗号化ファイルを作成し、複数のJSON文書を暗号化
  - decrypt   : 暗号化ファイルから特定のJSON文書を復号
  - update    : 暗号化ファイル内の特定文書を更新
  - generate  : シェアIDセットを生成
  - help      : ヘルプを表示
```

### 2. 主要コマンドの詳細

#### 2.1. シェア ID 生成コマンド

```
shamir-multi-crypt generate --size <シェア数> --output <ファイル名>

オプション:
  --size, -s      : 生成するシェアIDの数 (デフォルト: 100)
  --output, -o    : 出力ファイル名 (デフォルト: shares-{timestamp}.json)
  --ratio, -r     : A:B:未割当の比率 (デフォルト: "35:35:30")
```

このコマンドは以下の処理を行います：

- 指定数のシェア ID を生成
- 比率に基づいて A 用、B 用、未割当に分類
- JSON ファイルに保存（パスワードでの保護も可能）

#### 2.2. 暗号化コマンド

```
shamir-multi-crypt init --file-a <JSON_A> --file-b <JSON_B> --shares-a <シェアIDファイルA> --shares-b <シェアIDファイルB> --output <暗号化ファイル>

オプション:
  --file-a, -a    : 文書AのJSONファイルパス
  --file-b, -b    : 文書BのJSONファイルパス
  --shares-a      : 文書A用のシェアIDリストファイル
  --shares-b      : 文書B用のシェアIDリストファイル
  --output, -o    : 出力暗号化ファイル名
  --threshold, -t : 閾値（デフォルト: 3）
  --password-a    : 文書Aのパスワード（指定しない場合はプロンプト）
  --password-b    : 文書Bのパスワード（指定しない場合はプロンプト）
```

このコマンドは以下の処理を行います：

- 2 つの JSON 文書を読み込み
- シェア ID リストを読み込み
- パスワードをプロンプト（指定されていない場合）
- 暗号化処理を実行し、指定された出力パスに保存

#### 2.3. 復号コマンド

```
shamir-multi-crypt decrypt --input <暗号化ファイル> --shares <シェアIDファイル> --output <出力JSONファイル>

オプション:
  --input, -i     : 暗号化ファイルパス
  --shares, -s    : シェアIDリストファイル
  --output, -o    : 出力JSONファイル名（デフォルト: decrypted-{timestamp}.json）
  --password, -p  : パスワード（指定しない場合はプロンプト）
```

このコマンドは以下の処理を行います：

- 暗号化ファイルとシェア ID リストを読み込み
- パスワードをプロンプト（指定されていない場合）
- 復号処理を実行し、指定された出力パスに JSON を保存

#### 2.4. 更新コマンド

```
shamir-multi-crypt update --input <暗号化ファイル> --file <新JSONファイル> --shares <シェアIDファイル> --output <更新後ファイル>

オプション:
  --input, -i     : 元の暗号化ファイルパス
  --file, -f      : 新しいJSON文書ファイル
  --shares, -s    : シェアIDリストファイル
  --output, -o    : 更新後の暗号化ファイル名（デフォルト: 上書き）
  --password, -p  : パスワード（指定しない場合はプロンプト）
  --backup, -b    : 元ファイルのバックアップを作成（デフォルト: true）
```

このコマンドは以下の処理を行います：

- 元の暗号化ファイル、新しい JSON 文書、シェア ID リストを読み込み
- パスワードをプロンプト（指定されていない場合）
- 必要に応じて元ファイルのバックアップを作成
- 更新処理を実行し、結果を保存

### 3. グローバルオプション

全コマンド共通のオプション：

```
--verbose, -v   : 詳細なログ出力を有効化
--quiet, -q     : 出力を最小限に抑える
--log-file      : ログの出力先ファイル
--help, -h      : ヘルプを表示
--version       : バージョン情報を表示
```

## 実装ガイドライン

### 1. パスワード入力の安全な処理

```python
def prompt_password(prompt_text="パスワードを入力してください: "):
    """
    パスワードを安全にプロンプト

    Args:
        prompt_text: プロンプト表示テキスト

    Returns:
        入力されたパスワード
    """
    # getpassモジュールを使用して画面に表示せずにパスワード入力
    import getpass
    return getpass.getpass(prompt_text)
```

### 2. シェア ID リストの処理

```python
def load_share_ids(share_file):
    """
    シェアIDリストファイルを読み込み

    Args:
        share_file: シェアIDリストのJSONファイルパス

    Returns:
        シェアIDのリスト
    """
    # ファイル読み込み
    # JSONとして解析
    # シェアIDのリストを返却
```

### 3. ファイル処理の安全性確保

```python
def safe_write_file(data, output_path, backup=False):
    """
    ファイルの安全な書き込み

    Args:
        data: 書き込むデータ
        output_path: 出力先パス
        backup: 既存ファイルのバックアップを作成するか

    Returns:
        成功時True
    """
    # バックアップが有効な場合、既存ファイルをバックアップ
    # 一時ファイルに書き込み
    # 書き込み成功後、目的のパスに移動/リネーム
```

### 4. メイン CLI 関数

```python
def main():
    """CLI エントリーポイント"""
    # コマンドライン引数のパース
    # サブコマンドに応じた処理の分岐
    # エラーハンドリングと適切なステータスコードでの終了
```

### 5. コマンド実装例

```python
def encrypt_command(args):
    """init サブコマンドの実装"""
    # 引数の検証
    # 必要なファイルの読み込み
    # パスワードプロンプト（必要な場合）
    # 暗号化モジュールの呼び出し
    # 結果の保存
    # 成功メッセージの表示

def decrypt_command(args):
    """decrypt サブコマンドの実装"""
    # 引数の検証
    # 必要なファイルの読み込み
    # パスワードプロンプト（必要な場合）
    # 復号モジュールの呼び出し
    # 結果の保存
    # 成功メッセージの表示
```

## セキュリティ上の注意点

### 1. パスワード取り扱い

- **メモリ保持の最小化**: パスワードはメモリ上に保持する時間を最小限に
- **環境変数の禁止**: パスワードを環境変数に保存しない
- **ヒストリー対策**: コマンドラインオプションより対話的入力を優先
- **安全なプロンプト**: `getpass`モジュールなどを使用して画面に表示しない

### 2. エラーメッセージと情報漏洩

- **汎用エラーメッセージ**: エラーの詳細が機密情報を漏らさないよう注意
- **常に一定時間実行**: 無効なパスワードなどでも処理時間が変わらないよう考慮
- **同一失敗メッセージ**: 異なる失敗原因でも同じメッセージを表示

### 3. ファイル処理

- **アトミック操作**: ファイル更新は常にアトミックに行う
- **一時ファイルの保護**: 適切なパーミッションでの一時ファイル作成
- **残留データの防止**: 処理完了後に一時ファイルやメモリを適切にクリーンアップ

## ユーザービリティ

### 1. プログレス表示

```python
def show_progress(current, total, prefix='', suffix='', bar_length=50):
    """
    プログレスバーを表示

    Args:
        current: 現在の進捗
        total: 全体量
        prefix: プレフィックステキスト
        suffix: サフィックステキスト
        bar_length: バーの長さ
    """
    # プログレスバー表示ロジック
```

### 2. 色付き出力

```python
class Colors:
    """ANSI カラーコード"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def colorize(text, color):
    """テキストに色を付ける"""
    return f"{color}{text}{Colors.ENDC}"
```

### 3. ヘルプメッセージ

明確で詳細なヘルプメッセージを各コマンドに提供します：

```python
# コマンドの説明例
init_parser = subparsers.add_parser(
    'init',
    help='新規暗号化ファイルを作成し、複数のJSON文書を暗号化',
    description='2つのJSON文書（A・B）と各シェアIDセットを用いて暗号化ファイルを生成します。'
             '生成されたファイルは各パスワードとシェアIDセットで復号可能です。'
)
```

### 4. エラー処理とフィードバック

```python
def handle_error(error, verbose=False):
    """
    エラーを適切に処理して表示

    Args:
        error: 発生したエラー/例外
        verbose: 詳細表示モードか
    """
    # エラータイプに応じた処理
    # verboseモードの場合は詳細表示
    # 適切なエラーコードで終了
```

## リリースとパッケージング

### 1. バージョン管理

```python
__version__ = '1.0.0'

def show_version():
    """バージョン情報を表示"""
    print(f"shamir-multi-crypt version {__version__}")
    print("シャミア秘密分散法による複数平文復号システム")
```

### 2. エントリーポイント定義

`setup.py` または `pyproject.toml` でのエントリーポイント定義：

```python
# setup.py の例
setup(
    # ...その他の設定...
    entry_points={
        'console_scripts': [
            'shamir-multi-crypt=shamir_multi_crypt.cli:main',
        ],
    },
)
```

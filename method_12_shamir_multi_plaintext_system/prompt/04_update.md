# 更新モジュール実装ガイド

## 更新モジュールの目的

このモジュールは既存の暗号化ファイルに対して、A 文書または B 文書のいずれかを更新するためのものです。元の暗号化ファイルから必要な情報を取り出し、指定された文書のみを更新して新しい暗号化ファイルを生成します。

## 主要な機能と要件

### 1. 安全な一時ファイル処理

- **一時ファイルの保護**: 一時ファイルもシャミア秘密分散法で保護
- **アップデート用マップ**: パスワードから生成したマップを用いて一時ファイルアクセスを制御
- **ファイル上書き**: 削除前に一時ファイルを上書きして痕跡を残さない
- **例外時処理**: 処理中断時も一時ファイルを確実に削除

### 2. 文書の選択的更新

- **A または** B いずれかの更新: 一方の文書のみを更新可能（両方同時は不可）
- **他文書の保持**: 更新対象でない文書は変更せずに保持
- **メタデータの継承**: 可能な限り元ファイルのメタデータを継承

### 3. セキュリティモデル

- **シェアトークン**: `9jfhsyenehgr6hkwhjyhbweey6d` のような単一行の文字列
- **セキュリティ依存**: 全てのセキュリティはシェアトークンとパスワードの 2 要素に依存
- **占有領域制御**: シェアトークンは占有できる可能性範囲の MAP を生成するために使用
- **マッピング不要**: 暗号化ファイルに明示的なマッピング情報は含まれない

### 4. 更新プロセスの安全性確保

- **統計的区別不可能性の維持**: 更新後も A/B/未割当のシェアが統計的に区別できないこと
- **タイミング攻撃耐性**: 処理時間が入力に依存しないよう実装
- **ファイル拡散の防止**: 古いファイル、一時ファイルを安全に削除

## 更新プロセスの流れ

```
元ファイルを復号
↓
該当する文書を取得（A or B）
↓
新しい文書で置き換え
↓
元と同じシャミアパラメータで再暗号化
↓
新しいファイルとして出力（UUID更新）
↓
一時ファイルを安全に消去
```

## 主要関数の実装ガイド

### 1. 更新関数のメイン実装

```python
def update(encrypted_file, password, share_token, new_json_doc, output_file=None):
    """
    暗号化ファイルの特定文書を更新

    Args:
        encrypted_file: 元の暗号化ファイルパス
        password: 更新対象文書のパスワード
        share_token: 対象文書に対応するシェアトークン
        new_json_doc: 新しいJSON文書
        output_file: 出力ファイルパス（デフォルトは自動生成）

    Returns:
        str: 新しい暗号化ファイルパス
    """
    # 1. 元ファイルを読み込み
    # 2. パスワードとシェアトークンで対象文書を復号
    # 3. 復号できた場合、一時ファイルに安全に保存
    # 4. 元ファイルと同じ暗号化パラメータで再暗号化
    # 5. 新しいUUIDを生成
    # 6. 新しいファイルに書き出し
    # 7. 一時ファイルを安全に削除
```

### 2. 一時ファイル処理関数

```python
def create_secure_temp_file():
    """
    安全な一時ファイルを作成

    Returns:
        tuple: (file_obj, file_path) - ファイルオブジェクトとパス
    """
    # 1. UUIDを生成
    # 2. 安全なディレクトリパスを構築
    # 3. 一時ファイルを作成
    # 4. カスタムクリーンアップをセット

def store_retrieved_document(doc, password, temp_file_path):
    """
    復号された文書を一時ファイルに安全に保存

    Args:
        doc: 保存する文書
        password: 保護用パスワード
        temp_file_path: 一時ファイルパス

    Returns:
        bool: 成功した場合はTrue
    """
    # 1. 文書をシリアライズ
    # 2. シャミア秘密分散法で保護
    # 3. パスワードから鍵を導出
    # 4. AES-GCMで暗号化して保存

def retrieve_document_from_temp(temp_file_path, password):
    """
    一時ファイルから文書を安全に取得

    Args:
        temp_file_path: 一時ファイルパス
        password: 復号用パスワード

    Returns:
        dict: 取得したJSON文書
    """
    # 1. ファイルを読み込み
    # 2. パスワードから鍵を導出
    # 3. AES-GCMで復号
    # 4. シャミア秘密分散法で復元
    # 5. JSONとして解析

def secure_delete_temp_file(temp_file_path):
    """
    一時ファイルを安全に削除

    Args:
        temp_file_path: 削除する一時ファイルパス

    Returns:
        bool: 成功した場合はTrue
    """
    # 1. ファイルをゼロで上書き
    # 2. 続いてランダムデータで上書き
    # 3. ファイルサイズを0に切り詰め
    # 4. ファイルを削除
    # 5. 各ステップでエラー処理
```

### 3. 暗号化パラメータ抽出関数

```python
def extract_encryption_params(encrypted_data, password, share_token):
    """
    暗号化ファイルからパラメータを抽出

    Args:
        encrypted_data: 暗号化されたバイナリデータ
        password: 復号に使用するパスワード
        share_token: 使用するシェアトークン

    Returns:
        dict: 暗号化パラメータ
    """
    # 1. ファイルを復号
    # 2. メタデータからパラメータを抽出
    # 3. 必要なパラメータを辞書にまとめて返却

def encrypt_with_params(json_doc, password, share_token, unassigned_tokens, params):
    """
    既存パラメータを使って再暗号化

    Args:
        json_doc: 暗号化するJSON文書
        password: 暗号化に使用するパスワード
        share_token: 文書に対応するシェアトークン
        unassigned_tokens: 未割当のシェアトークンリスト
        params: 元ファイルから抽出した暗号化パラメータ

    Returns:
        bytes: 暗号化されたデータ
    """
    # 1. パラメータに基づいて暗号化
    # 2. 元ファイルと互換性のある形式で暗号化
    # 3. 新しいUUIDを生成
```

## 実装上の制約とガイドライン

### 1. 一時ファイルの取り扱い

ファイルの更新中に作成する一時ファイルは、情報漏洩のリスクを伴います。以下のガイドラインを厳守してください：

- **保存場所の制限**: 一時ファイルは安全なディレクトリにのみ保存
- **暗号化の義務化**: 一時ファイルも必ず暗号化して保存
- **ダブルシャミア禁止**: 一時ファイルに複数平文機能は使わず、単一のシャミア秘密分散法で保護
- **メモリ上保持**: 可能な限りディスクに書き出さずにメモリ上で処理
- **確実な削除**: finally ブロックを使用して、例外発生時も確実に削除

### 2. エラー処理の方針

- **リカバリーメカニズム**: 更新処理中に失敗した場合、元のファイルを保持
- **アトミック更新**: 更新処理が完全に成功した場合のみ新ファイルを有効化
- **エラー情報の最小化**: エラーメッセージから機密情報が漏れないよう注意

### 3. 再暗号化のセキュリティ要件

- **UUID の更新**: 新しいファイルには新しい UUID を付与
- **ソルトの更新**: 新しいランダムソルトを生成（再利用しない）
- **セキュリティパラメータの継承**: 閾値や素数などのパラメータは継承
- **シェア配置の再シャッフル**: 新しいシェア配置は統計的に独立にシャッフル

### 4. ファイル管理戦略

- **元ファイルの扱い**: デフォルトでは元ファイルを残し、オプションで削除可能
- **バックアップの推奨**: 更新前に元ファイルのバックアップを推奨
- **命名規則**: `encrypted_{timestamp}_{uuid}.henc` の形式で命名
- **一時ファイル命名**: `temp_{timestamp}_{uuid}.tmp` の形式で一意に命名

### 5. 安全な一時ファイル作成のための追加関数

```python
def secure_temporary_file(prefix="temp", suffix=".bin"):
    """
    安全な一時ファイルを作成

    Args:
        prefix: ファイル名の接頭辞
        suffix: ファイル名の接尾辞

    Returns:
        tuple: (file_obj, file_path) - ファイルオブジェクトとパス
    """
    # UUIDを生成
    # 安全なディレクトリパスを構築
    # 一時ファイルを作成
    # カスタムクリーンアップをセット

def secure_overwrite(file_path, passes=3):
    """
    ファイルを安全に上書きして削除

    Args:
        file_path: 削除するファイルのパス
        passes: 上書き回数

    Returns:
        bool: 成功した場合はTrue
    """
    # ファイルサイズを取得
    # 複数回の上書き処理
    # ファイルを切り詰めて削除

def clean_memory_variable(variable):
    """
    メモリ変数を安全にクリア

    Args:
        variable: クリアする変数（バイト列やリスト）
    """
    # 変数タイプに応じてゼロデータで上書き
    # 可能であれば明示的に解放
```

## 更新処理実行フローの詳細

### 1. 元ファイルの検証と読み込み

```
元暗号化ファイルを読み込み
↓
ファイルフォーマットを検証
↓
パスワードとシェアトークンで対象文書を復号
↓
復号できた場合、安全な一時ファイルに文書を保存
```

### 2. パラメータ抽出と再暗号化

```
元ファイルから暗号化パラメータを抽出
↓
新しい文書を用意
↓
元のパラメータ（閾値、素数など）を使用
↓
新しいUUIDとソルトを生成
↓
再暗号化を実行
```

### 3. 出力とクリーンアップ

```
新しいファイル名を生成（タイムスタンプ+UUID）
↓
暗号化データを新ファイルに書き出し
↓
一時ファイルを安全に削除
↓
（オプション）元ファイルを安全に削除
↓
新ファイルパスを返却
```

## セキュリティ上の注意点

1. **メモリ内保持時間の最小化**:

   - 復号された平文文書のメモリ内保持時間を最小限に抑える
   - 不要になった時点で即座にメモリ変数をゼロで上書き

2. **一時ファイルの暗号強度**:

   - 一時ファイルも本ファイルと同等の暗号強度で保護
   - シャミア秘密分散法と AES-GCM の二重保護を適用

3. **ファイル命名のセキュリティ**:

   - ファイル名から内容が推測できないようにする
   - UUID + タイムスタンプで一意性を確保

4. **途中経過の分離**:

   - A 文書と B 文書の途中経過が混在しないよう注意
   - それぞれを別々の一時ファイルで処理

5. **エラー時の情報漏洩防止**:
   - エラー発生時も情報漏洩が起きないよう確実に一時ファイル削除
   - エラーメッセージが処理内容を示唆しないよう設計

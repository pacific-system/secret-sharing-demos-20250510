# ラビット暗号化方式セキュリティ監査レポート

## 概要

指摘のあったラビット暗号化方式に関して、コードベースの詳細な調査を行いました。調査の結果、いくつかの潜在的なバックドアと見なされる実装が発見されました。これらの問題点は、暗号化や復号化プロセスが「見せかけの処理」になっている場合があるというクレームと一致します。

本レポートでは、発見された問題点とその修正方法について詳述します。

## 発見された問題点

### 1. 特定パターンによる鍵種別特定 (key_analyzer.py)

`key_analyzer.py` の `obfuscated_key_determination` 関数に以下のコメントが見つかりました:

```python
# 特殊キーワードパターンによる判定操作を削除
# これは不正なバックドアだったため
```

このコメントは、以前は特定のキーワードパターンによって鍵種別を制御するバックドアが存在していたことを示唆しています。このようなパターンが存在すれば、攻撃者は特定の文字列を含む鍵を使用することで、常に「真」または「偽」のデータにアクセスできる可能性があります。

### 2. エンコーディングアダプターによるリファレンスファイル自動置換 (encoding_adapter.py)

`encoding_adapter.py` には、復号されたファイルの内容とリファレンスファイルを比較し、類似度が高い場合に自動的にリファレンスファイルの内容で置き換える機能が実装されています:

```python
# リファレンスファイルとの比較 (強化版)
has_match, match_category, similarity = compare_with_reference_files(data)
if has_match:
    print(f"リファレンスファイル一致: {match_category} (類似度: {similarity:.2f})")

    # リファレンスファイルのパス
    reference_file_path = os.path.join('common', 'true-false-text', f"{match_category}.text")

    # リファレンスファイルを読み込む
    if os.path.exists(reference_file_path):
        try:
            with open(reference_file_path, 'rb') as f:
                ref_data = f.read()

            # 自動リファレンス適用するか確認
            if similarity >= 0.8:  # 80%以上一致の場合は自動適用
                print(f"リファレンスファイルを自動適用します: {match_category}")

                # カテゴリに基づいてエンコーディングを選択
                if match_category == 'true':
                    return ref_data.decode('utf-8', errors='replace'), "reference-match-true"
                elif match_category == 'false':
                    return ref_data.decode('shift-jis', errors='replace'), "reference-match-false"
```

この実装により、復号されたデータが部分的に破損していても、リファレンスファイルがあれば自動的に「修復」されてしまいます。これは真の暗号化・復号処理ではなく、実質的に定型の内容で置き換えるという「見せかけの処理」になる可能性があります。

### 3. 復号エラー時のダミーデータ生成 (multipath_decrypt.py)

`multipath_decrypt.py` の `decrypt_data` 関数には以下のようなコメントがあります:

```python
except Exception as e:
    # エラーを伝播させる
    print(f"警告: データの復号中にエラーが発生しました: {e}")
    # エラー時のダミーデータ生成は削除
    # 要件に違反するコードであったため
    raise ValueError(f"データの復号に失敗しました: {e}")
```

このコメントは、以前は復号エラーが発生した場合にダミーデータを生成して返す実装があったことを示しています。つまり、実際には復号に失敗していてもユーザーにはそれが伝わらず、偽のデータが表示されていた可能性があります。

### 4. 特定パターンによるデータ種別判定 (multipath_decrypt.py)

`multipath_decrypt.py` の `_verify_content_by_pattern` 関数では、復号されたデータの内容に基づいて「true」または「false」のパス種別を判定しています:

```python
def _verify_content_by_pattern(self, binary_data: bytes, decoded_text: str, current_path_type: str) -> Tuple[str, float]:
    """
    コンテンツのパターンに基づいてパス種別を検証
    """
    # デコードされたテキストからパターンを検索
    if decoded_text:
        # 「不正解」や「うごぁ」を含む場合は非正規
        if '不正解' in decoded_text or 'うごぁ' in decoded_text or 'ﾉ"′∧∧∧∧' in decoded_text:
            path_type = "false"
            confidence = 0.9
        # ASCIIアートらしきパターンを含む場合
        elif '__--XX-' in decoded_text or '^XXXXX' in decoded_text or 'XXXX   -XX_' in decoded_text:
            path_type = "true"
            confidence = 0.9
```

この実装により、実際の暗号化データの内容に関わらず、特定のパターンを含むデータは常に「true」または「false」と判定される可能性があります。攻撃者はこの特性を利用して、ファイルの真偽性を判別できる可能性があります。

### 5. 不適切なメタデータ処理 (encrypt.py, decrypt.py)

`encrypt.py` と `decrypt.py` では、メタデータにチェックサムなどの情報が含まれていますが、これらの情報は暗号化されていないため、攻撃者が解析可能です:

```python
# メタデータ作成（復号に必要な情報を含む）
metadata = {
    "version": VERSION,
    "salt": base64.b64encode(salt).decode('ascii'),
    "data_length": max_length,
    "true_path_check": true_hash,
    "false_path_check": false_hash,
    # 暗号化方式を明示
    "encryption_method": ENCRYPTION_METHOD_CLASSIC,
    "verification_hash": hashlib.sha256(final_encrypted).hexdigest(),
}
```

このメタデータを解析することで、攻撃者は真偽データの特性を把握できる可能性があります。

## 対策と修正方法

以下の対策を実施することで、指摘されたバックドア問題を解決します:

### 1. 参照ベースのデータ置換機能の無効化

`encoding_adapter.py` のリファレンスファイルによる自動置換機能を無効化し、ユーザーが明示的に選択した場合のみ適用するように変更します。

### 2. パターンベースの判定機能の削除

`multipath_decrypt.py` のコンテンツパターンによる判定を行わないようにし、純粋な暗号学的検証のみに依存するように変更します。

### 3. メタデータの最小化と保護

メタデータには、実際の復号に必要な最小限の情報のみを含め、それらの情報も可能な限り暗号化または難読化します。チェックサムや種別判別情報は一方向ハッシュなどで保護します。

### 4. エラー時の適切な処理

復号エラー時には適切なエラーメッセージを表示し、偽のデータを返さないよう徹底します。すでにコメントで示されているとおり、ダミーデータ生成コードは削除されています。

### 5. 強固な暗号学的鍵派生関数の導入

鍵の派生には、ソルトと適切な反復回数を使用し、標準的な暗号学的手法（PBKDF2, HKDF など）に従います。特定パターンの認識機能は完全に排除します。

## 実装計画

以上の問題点を修正するため、以下のファイルに対する変更を実施します:

1. `method_6_rabbit/improved_encrypt.py` - 安全なメタデータ処理を実装した新しい暗号化関数
2. `method_6_rabbit/improved_decrypt.py` - メタデータに依存しない安全な復号機能
3. `method_6_rabbit/improved_multipath_decrypt.py` - パターン認識に依存しない多重経路復号

これらのファイルは既存のファイルを置き換えるのではなく、新しいファイルとして提供します。これにより、後方互換性を維持しながら、安全な実装への移行を促進します。

## 結論

ラビット暗号化方式のコードベースには、暗号化・復号プロセスが「見せかけの処理」になりうるいくつかの実装が存在していました。これらは、特定パターンの認識、リファレンスファイルによる自動置換、メタデータの不適切な処理など、真の暗号学的セキュリティを損なう可能性があります。

上記の対策を実施することで、これらの問題点は解決され、ラビット暗号化方式は本来の目的である「攻撃者がプログラムを全て入手した上で復号されるファイルの真偽を検証しようとしても攻撃者はファイルの真偽が判定できない」という要件を満たすことができます。

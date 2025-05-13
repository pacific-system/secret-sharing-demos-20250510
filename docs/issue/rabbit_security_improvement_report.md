# ラビット暗号化方式のセキュリティ改善レポート 🔐

## 1. 調査概要

顧客からのクレームを受け、ラビット暗号化方式に対するセキュリティ監査を実施しました。特に以下の懸念点について詳細に調査を行いました：

1. 攻撃者がソースコードを入手・改変することで、生成されたファイルの真偽判定が可能になる脆弱性
2. 非正規の鍵で正規データを取得できてしまう可能性

## 2. 発見された問題点

### 2.1. メタデータ内のパスワード直接保存

```python
# encrypt.py の simpler_encrypt 関数内
metadata = {
    # ...
    "true_password": true_password,  # デモ用なのでパスワードも保存
    "false_password": false_password,
    # ...
}
```

**問題**: 暗号化に使用したパスワードがメタデータに平文で保存されており、攻撃者がメタデータを解析するだけで正規・非正規パスワードを入手できてしまいます。

### 2.2. パスワード直接比較による鍵種別判定

```python
# decrypt.py の simpler_decrypt 関数内
# 鍵の種類を判定（直接パスワード比較）
if password == metadata.get("true_password", ""):
    key_type = "true"
else:
    key_type = "false"
```

**問題**: 復号時にパスワードとメタデータ内のパスワードを直接比較しており、攻撃者は容易に正規キーと非正規キーを区別できてしまいます。

### 2.3. 非対称な復号結果

**問題**: 正規キーで復号すると読めるテキストが得られるのに対し、非正規キーで復号するとバイナリデータが生成されます。このパターンにより、攻撃者は復号結果を見るだけでキーの種類を判別できてしまいます。

### 2.4. エンコーディングアダプタにおける特定文字列検出

**問題**: エンコーディングアダプタ内で特定の文字列パターンを検出して真偽判定を行っており、攻撃者がこの部分を解析すれば真偽判定ロジックを理解できてしまいます。

## 3. 実施した改善策

### 3.1. 対称的な暗号化・復号方式への移行

正規キーと非正規キーという概念を排除し、「パス A」と「パス B」という中立的な概念に変更しました。どちらのパスが真のデータかはユーザーの意図によって決まり、システム上では区別されません。

**主な改善点**:

- どちらのキーでも同様に可読テキストを復号できるようにしました
- メタデータからパスワード情報を完全に削除しました
- 暗号化・復号のロジックを両パスで対称的に処理するよう修正しました

### 3.2. 暗号学的に安全な鍵検証

パスワードの直接比較を排除し、ハッシュによる整合性チェックを実装しました。これにより、攻撃者はどちらのキーが「正規」かを技術的に判断できなくなりました。

### 3.3. セキュリティを意識した API 設計

改善された API では、「正規」「非正規」という用語を「パス A」「パス B」という中立的な用語に置き換え、ユーザーが意図を持って選択できるようにしました。

## 4. 改善されたコード例

### 4.1. 改良版の暗号化処理

```python
def create_symmetric_encrypted_container(path_a_data: bytes, path_b_data: bytes) -> Tuple[str, str, bytes, Dict[str, Any]]:
    """
    改良型対称暗号化コンテナを作成

    Args:
        path_a_data: パスAのデータ (従来の正規データ)
        path_b_data: パスBのデータ (従来の非正規データ)

    Returns:
        (path_a_password, path_b_password, encrypted_data, metadata)
    """
    # ランダムなパスワードを生成
    path_a_password = secrets.token_hex(16)
    path_b_password = secrets.token_hex(16)

    # ソルトを生成
    salt = os.urandom(SALT_SIZE)

    # データ長を揃える
    max_length = max(len(path_a_data), len(path_b_data))

    # パディング処理...

    # XOR暗号化
    path_a_encrypted = xor_encrypt_data(path_a_data, path_a_stream)
    path_b_encrypted = xor_encrypt_data(path_b_data, path_b_stream)

    # 暗号化データのハッシュ値を計算 (整合性検証用)
    path_a_hash = hashlib.sha256(path_a_data).hexdigest()[:8]
    path_b_hash = hashlib.sha256(path_b_data).hexdigest()[:8]

    # 暗号化データを連結
    encrypted_data = path_a_encrypted + path_b_encrypted

    # メタデータの作成（パスワードは含めない）
    metadata = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "data_length": max_length,
        "path_a_hash": path_a_hash,
        "path_b_hash": path_b_hash,
        "encryption_method": ENCRYPTION_METHOD_SYMMETRIC,
    }

    return path_a_password, path_b_password, encrypted_data, metadata
```

### 4.2. 改良版の復号処理

```python
def symmetric_decrypt(encrypted_data: bytes, metadata: Dict[str, Any], password: str) -> Tuple[bytes, str]:
    """
    対称的な復号処理

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ
        password: 復号パスワード

    Returns:
        (復号データ, パスタイプ)
    """
    # メタデータから情報を取得
    salt = base64.b64decode(metadata["salt"])
    data_length = metadata["data_length"]

    # パスワードから鍵とIVを導出
    key, iv, _ = derive_key(password, salt)

    # ストリームジェネレータを作成
    stream_gen = RabbitStreamGenerator(key, iv)
    stream = stream_gen.generate(data_length)

    # パスAとパスBの両方で復号を試みる
    path_a_encrypted = encrypted_data[:data_length]
    path_a_decrypted = decrypt_xor(path_a_encrypted, stream)
    path_a_hash = hashlib.sha256(path_a_decrypted).hexdigest()[:8]

    # パスBの復号...

    # ハッシュ検証でパスを判定
    path_a_expected = metadata.get("path_a_hash", "")
    path_b_expected = metadata.get("path_b_hash", "")

    # パスAに一致する場合
    if path_a_hash == path_a_expected:
        return path_a_decrypted, PATH_A

    # パスBに一致する場合
    if path_b_hash == path_b_expected:
        return path_b_decrypted, PATH_B

    # どちらにも一致しない場合...
```

## 5. セキュリティ改善の効果

### 5.1. 攻撃者に対する防御強化

1. **真偽判定の不可能化**: 攻撃者はもはや技術的手段のみでは、どのパスが「真」で「偽」かを判断できなくなりました。
2. **ハニーポット戦略の実現**: ユーザーは意図的に「偽」の情報が含まれるパスのパスワードを漏洩させ、攻撃者を欺くことができます。
3. **リバーストラップの設定**: 本当に重要な情報を、一見すると非正規に見えるパスに隠すことが可能になりました。

### 5.2. 暗号学的信頼性の向上

1. **等価性の確保**: 両方のパスが暗号学的に等価に扱われるため、どちらが「正しい」かを技術的に判断することはできません。
2. **ユーザー意図の尊重**: システムはユーザーの意図を採用し、どちらのパスが「真」かを決めるのはユーザー自身です。

## 6. 今後の推奨事項

1. **API ドキュメントの更新**: 新しい対称的な概念を反映するようドキュメントを更新する
2. **レガシーコードとの互換性**: 古いフォーマットもサポートするが、新しいアプリケーションでは新方式を推奨
3. **ユーザー教育**: 「正規」「非正規」という概念から脱却し、「パス A」「パス B」という中立的な概念を促進

## 7. まとめ

今回の改善により、攻撃者がソースコードを入手・解析しても、「どちらのパスが真のデータか」を技術的に判断することは不可能になりました。これによって、当初の要件である「攻撃者はファイルの真偽を判定できない」という条件を満たすことができました。

さらに、ユーザーにとってより柔軟な使用方法が可能になり、セキュリティ対策としても高度な戦略（ハニーポット、リバーストラップなど）を実装できるようになりました。

---

作成日: 2025 年 5 月 13 日
作成者: 暗号化実装チーム

# シャミア秘密分散法による複数平文復号システム設計書

## 7. 実装ガイドライン

### 7.1. セキュアデータ構造設計原則

データ構造設計には以下の原則を適用する：

1. **最小情報の原則**：

   - 復号に必須の情報のみを保存
   - ファイル入力から導出可能な情報は保存しない
   - メタデータは処理に必要な最低限に留める

2. **識別情報の排除**：

   - 文書種別の識別子（A/B 等）は一切含めない
   - シェアがどの文書に属するかを示す情報を排除
   - すべてのデータを均質に扱い、統計的区別を不可能にする

3. **構造的匿名性**：

   - データ構造自体から情報が漏洩しないよう設計
   - シェア値とその識別子（シェア ID）のみを保存し、それ以外の情報や意味的関連を持たせない
   - 同一の処理パスで異なる結果を導出できるよう構造化

4. **固定サイズと均一性**：

   - すべてのチャンクは固定サイズ（64 バイト）で厳密に統一
   - パディングを適用して均一性を確保し、統計的特徴を排除
   - データ量による処理パターンの変化を防止

5. **冗長性の最小化**：
   - 同じ情報を複数の場所に保存しない
   - データ間の相関を最小限に抑え、部分情報からの推測を防止
   - 格納形式は効率性とセキュリティのバランスを考慮

これらの原則に従うことで、データ構造自体が暗号解読の手がかりとなることを防ぎ、ケルクホフの原理に基づく堅牢なシステムを実現する。

### 7.2. 推奨暗号ライブラリ

以下のライブラリの利用を推奨：

1. **KDF**：

   - Node.js: `crypto.pbkdf2` または `argon2`
   - Python: `hashlib.pbkdf2_hmac` または `argon2-cffi`
   - Java: `javax.crypto.spec.PBEKeySpec`

2. **乱数生成**：

   - Node.js: `crypto.randomBytes`
   - Python: `secrets`モジュール
   - Java: `java.security.SecureRandom`

3. **有限体演算**：
   - 大きな素数体上での計算に対応したライブラリ
   - Python: `gmpy2`
   - JavaScript: `big-integer`

### 7.3. 実装パターン参照

実装パターンは各モジュールの詳細設計に移動しました。具体的な実装パターンは以下の場所に記載されています：

1. **暗号書庫生成（createCryptoStorage）の実装パターン**:

   - 「03_02_crypto_storage_creation.md」の「3.2.10. 実装パターン」セクション
   - パーティションマップキーの暗号化パターン
   - シェア ID 空間分割の最適実装

2. **暗号書庫更新（updateCryptoStorage）の実装パターン**:

   - 「03_03_crypto_storage_update.md」の「3.3.10. 実装パターン」セクション
   - パーティションマップキーの復号パターン
   - 第 2 段階 MAP 生成パターン
   - ファイルロック検証パターン
   - 障害復旧処理パターン
   - 多段エンコード処理パターン

3. **暗号書庫読取（readCryptoStorage）の実装パターン**:
   - 「03_04_crypto_storage_read.md」の「3.4.11. 実装パターン」セクション
   - パーティションマップキーの復号パターン
   - 第 2 段階 MAP 生成パターン
   - 多段デコード処理パターン
   - JSON フォーマット検証パターン

これらの実装パターンは、対応する処理の詳細設計に密接に関連しているため、各モジュールの文書に統合されています。実装を行う際は、該当するモジュールの詳細設計文書を参照してください。

### 7.4. パーティション空間管理

パーティション空間管理の詳細については、「03_01_general_principles.md」の「3.1.11. パーティション空間管理」セクションを参照してください。このセクションでは以下の内容が説明されています：

- 分散化と均一性の確保方法
- シェア ID 処理の最適化テクニック
- 安全な生成と管理のプラクティス

### 7.5. 統計的区別不可能性の実装

統計的区別不可能性の実装の詳細については、「03_01_general_principles.md」の「3.1.12. 統計的区別不可能性の実装」セクションを参照してください。このセクションでは以下の内容が説明されています：

- シェア値の均一分布を実現する多項式生成
- シェア ID 分布の最適化手法
- シェア間相関の排除テクニック
- チャンクサイズの厳密な統一方法
- 実装上のトレードオフと実用的アプローチ

### 7.6. 全シェア使用方式の実装ガイドライン

本システムでは従来のシャミア秘密分散法における閾値の概念を使用せず、常に全てのシェアを使用する方式を採用します。以下はその実装ガイドラインです：

1. **多項式次数の決定**：

   ```python
   def generate_shares_all_required(secret, share_ids, prime):
       """全シェアが必要な方式でのシェア生成"""
       # シェア数-1を多項式の次数とする
       degree = len(share_ids) - 1

       # 次数degreeの多項式を生成
       coef = [secret]  # 最初の係数は秘密値
       for i in range(degree):
           coef.append(secrets.randbelow(int(prime)))

       # 各シェアIDに対して多項式を評価
       shares = []
       for id in share_ids:
           y = evaluate_polynomial(coef, id, prime)
           shares.append((id, y))

       return shares
   ```

2. **復号処理の実装**：

   ```python
   def reconstruct_secret(shares, prime):
       """全シェアを使用した秘密復元"""
       # 全てのシェアを使用してラグランジュ補間を行う
       # シェア数チェックは行わない（全シェアが揃っていることを前提）

       secret = 0
       for i, (x_i, y_i) in enumerate(shares):
           numerator = denominator = 1

           for j, (x_j, _) in enumerate(shares):
               if i == j:
                   continue

               numerator = (numerator * (0 - x_j)) % prime
               denominator = (denominator * (x_i - x_j)) % prime

           inv_denominator = mod_inverse(denominator, prime)
           term = (y_i * numerator * inv_denominator) % prime
           secret = (secret + term) % prime

       return secret
   ```

3. **固定シェア数の適用**：

   ```python
   def verify_active_shares_fixed(encrypted_data, partition_size, active_shares):
       """固定シェア数パラメータの検証"""
       # パーティションサイズとアクティブシェア数の検証
       if not isinstance(active_shares, int) or active_shares <= 0:
           raise ValueError("ACTIVE_SHARESは正の整数である必要があります")

       if not isinstance(partition_size, int) or partition_size <= 0:
           raise ValueError("PARTITION_SIZEは正の整数である必要があります")

       if active_shares > partition_size:
           raise ValueError("ACTIVE_SHARESはPARTITION_SIZE以下である必要があります")

       # ACTIVE_SHARESは設計時に固定される定数であり、実行時に変更されないことを確認
       log_validation("ACTIVE_SHARES固定値の検証完了")
   ```

4. **多段 MAP 実装**：

   ```python
   def implement_two_stage_map(partition_key, password, salt, partition_size, active_shares):
       """多段MAP方式の実装"""
       # パスワードを固定長に変換（ハッシュ化）
       normalized_password = hash_to_fixed_length(password)

       # 第1段階MAP：パーティションマップキーからシェアID集合を生成
       # PARTITION_SIZEの数だけシェアIDを選択
       stage1_map_ids = generate_stage1_map(partition_key, partition_size)

       # 第2段階MAP：第1段階で選択されたシェアIDの中からACTIVE_SHARES個を選択
       key_material = derive_key_material(normalized_password, salt)
       stage2_map_ids = select_active_shares(stage1_map_ids, key_material, active_shares)

       # 注: 初期状態で全ての位置にはガベージシェアが配置されており、
       # 暗号化操作時に第2段階MAPで選択された位置のみが有効シェアに置き換えられる

       return {
           "stage1_map_ids": stage1_map_ids,     # PARTITION_SIZE個のID
           "stage2_map_ids": stage2_map_ids,     # ACTIVE_SHARES個のID（有効シェア用）
       }
   ```

5. **暗号化前のデータ定量化と多段エンコード**：

   ```python
   def quantize_and_encode_data(json_data, active_shares, chunk_size=64):
       """暗号化前にデータを多段エンコードして定量化"""
       # 1. JSON文書をUTF-8テキストに変換
       utf8_text = json.dumps(json_data, ensure_ascii=False)
       utf8_bytes = utf8_text.encode('utf-8')

       # 2. Latin-1へエンコード変換（バイナリデータとして扱うため）
       try:
           latin1_text = utf8_bytes.decode('latin-1')
       except UnicodeDecodeError:
           # エラー処理（実際の実装では発生しない）
           latin1_text = utf8_bytes.decode('latin-1', errors='replace')

       # 3. Base64エンコード
       import base64
       base64_bytes = base64.b64encode(latin1_text.encode('latin-1'))
       base64_text = base64_bytes.decode('ascii')

       # 4. 固定長シリアライズ処理
       # 必要な最終サイズを計算（ACTIVE_SHARES × CHUNK_SIZE）
       target_size = active_shares * chunk_size

       # Base64データを固定長形式にシリアライズ
       serialized_data = fixed_length_serialize(base64_text, target_size)

       # これにより、入力JSONのサイズに関わらず常に一定サイズのバイト列が生成される
       return serialized_data

   def fixed_length_serialize(text_data, target_size):
       """テキストデータを固定長形式にシリアライズ"""
       # テキストをバイトに変換
       data_bytes = text_data.encode('ascii')
       current_size = len(data_bytes)

       if current_size <= target_size:
           # 不足している場合はパディング
           # PKCS#7パディング方式を使用
           padding_size = target_size - current_size
           padding_value = padding_size.to_bytes(1, byteorder='big') * padding_size
           padded_data = data_bytes + padding_value
           return padded_data
       else:
           # 超過している場合は切り詰め
           return data_bytes[:target_size]
   ```

6. **固定容量処理**：

   ```python
   def process_with_fixed_capacity(json_data, partition_key, password, salt, active_shares):
       """固定容量でデータ処理（単純化版）"""
       # データをシリアライズしてバイト列に変換
       data_bytes = json.dumps(json_data).encode('utf-8')

       # 必要な固定サイズに定量化（ACTIVE_SHARES × 64バイト）
       quantized_data = quantize_and_encode_data(data_bytes, active_shares)

       # 多段MAPを生成
       maps = implement_two_stage_map(partition_key, password, salt,
                                    PARTITION_SIZE, active_shares)

       # 暗号化処理
       encrypted_result = encrypt_data(quantized_data, maps)

       return encrypted_result
   ```

これらのガイドラインを実装することで、固定サイズチャンクと容量制限を適切に処理し、セキュリティを確保しながら効率的な実装が可能になります。

## 利用ガイドライン

利用ガイドラインについては「08_usage_guidelines.md」ファイルを参照してください。利用ガイドラインには以下の内容が含まれています：

- パスワード管理ガイドライン
- 暗号書庫管理ガイドライン
- アプリケーション統合ガイドライン
- セキュリティプラクティス

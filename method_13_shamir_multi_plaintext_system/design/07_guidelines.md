# シャミア秘密分散法による複数平文復号システム設計書

## 7. 実装ガイドライン

### 7.1. セキュアデータ構造設計原則

データ構造設計には以下の原則を適用する：

1. **最小情報の原則**：

   - 復号に必須の情報のみを保存
   - ユーザー入力から導出可能な情報は保存しない
   - メタデータは処理に必要な最低限に留める

2. **識別情報の排除**：

   - 文書種別の識別子（A/B 等）は一切含めない
   - シェアがどの文書に属するかを示す情報を排除
   - すべてのデータを均質に扱い、統計的区別を不可能にする

3. **構造的匿名性**：

   - データ構造自体から情報が漏洩しないよう設計
   - シェア値とその識別子のみを保存し、意味的関連を持たせない
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

### 7.3. 条件分岐の禁止と定数時間処理の実装パターン

以下のパターンは条件分岐によるサイドチャネル攻撃を防止するために重要である。**すべての条件分岐を含むコードパターンは本システムでは禁止とする**。

1. **選択操作**：

```python
# ⛔ 禁止: 条件分岐を使った選択
result = value_a if condition else value_b

# ✅ 推奨: 定数時間選択を使用（ビット演算による実装）
mask = -int(condition)  # True -> -1 (全ビット1), False -> 0 (全ビット0)
# Pythonの整数は任意精度なのでビット長を気にする必要がない
result = (value_a & mask) | (value_b & ~mask)
```

2. **ループ処理**：

```python
# ⛔ 禁止: 早期リターンを使用
for share in shares:
    if is_valid(share):
        return share

# ✅ 推奨: 全要素を一定時間で処理
selected_share = None
selected_idx = -1
for i in range(len(shares)):
    # 最初の有効なシェアのインデックスをマスク付き比較で記録
    is_valid_share = is_valid(shares[i])
    should_select = is_valid_share and selected_idx == -1
    # ビット演算でインデックスと値を条件分岐なしで更新
    mask = -int(should_select)
    selected_idx = (selected_idx & ~mask) | (i & mask)
    selected_share = (selected_share & ~mask) | (shares[i] & mask)
```

3. **例外処理**：

```python
# ⛔ 禁止: try-exceptを使用した条件分岐
try:
    return json.loads(data)
except:
    return None

# ✅ 推奨: 例外を発生させない処理
def safe_json_parse(data):
    """安全にJSONを解析する関数"""
    # データをチェックして安全に解析
    if not isinstance(data, str):
        return {'value': None, 'error': 'データが文字列ではありません'}
    if len(data) == 0:
        return {'value': None, 'error': '空文字列です'}
    # ... 他のチェック

    # 解析結果をラップ
    result = {'value': None, 'error': None}
    try:
        result['value'] = json.loads(data)
    except Exception as e:
        # 例外を記録するが、処理は続行
        result['error'] = str(e)
    return result
```

4. **容量チェック**：

```python
# ⛔ 禁止: 容量による条件分岐
if data_size > max_size:
    raise CapacityError("容量超過")
else:
    encrypt_data(data)

# ✅ 推奨: 容量チェック結果を変数に保存し、処理を続行
is_within_capacity = data_size <= max_size
# 結果を記録（ログやメトリクスなど）
log_capacity_check(is_within_capacity)
# ビット演算で処理結果を選択
result = process_within_capacity(data) if is_within_capacity else create_error_result()
return result
```

注意: 実装のすべての部分で条件分岐を避け、定数時間アルゴリズムを使用することは、このシステムのセキュリティモデルにおいて**絶対的要件**である。ここで示した禁止パターンを使用した実装は、タイミング攻撃に対して脆弱となるため、許容されない。

### 7.4. パーティション空間管理

パーティション空間の効率的かつ安全な管理のための指針：

1. **分散化と均一性**：

   - パーティションマップキーの分布はランダム性を維持し、パターンを形成しない
   - 任意の連続範囲において、各種別（A/B/未割当）の分布比率が一定となるよう設計
   - ブロック単位での分布検証を実施し、統計的均一性を確保

2. **効率的なルックアップ**：

   - 頻繁なパーティションマップキー検索に対応するため、効率的なデータ構造を採用
   - パーティションマップキーの検索や所属確認において条件分岐を用いない実装
   - ビット演算やルックアップテーブルを活用した定数時間アクセス

3. **安全な生成と管理**：
   - 暗号学的に安全な乱数発生器を用いたパーティション空間の生成
   - 初期化時にのみ ID 割り当てを行い、以後は変更しない
   - 割り当て情報は 4 つの要素（両パスワードと両パーティションマップキーセット）なしには再構築不可能

### 7.5. 統計的区別不可能性の実装

統計的区別不可能性を確保するための具体的実装方法を以下に示す：

1. **シェア値の均一分布**：

   - シャミア秘密分散法の数学的特性上、多項式の係数をランダムに選択すると、結果として生成されるシェア値は有限体上で均一分布する
   - 実装方法：
     ```python
     def generate_polynomial(secret, degree, p):
         """degree次の多項式を生成（係数は完全ランダム）"""
         coef = [secret]  # 最初の係数は秘密値
         # 残りの係数は完全なランダム値
         for i in range(degree):
             coef.append(secrets.randbelow(p))
         return coef
     ```
   - この実装により、生成されるシェア値は統計的に区別不可能になる

2. **シェア ID 分布の最適化**：

   - 連続した ID（1,2,3...）の使用を避け、ランダム分布させた ID を使用
   - 実装方法：
     ```python
     def generate_share_ids(n, id_space_size=2**32):
         """ランダムなシェアIDをn個生成"""
         ids = set()
         while len(ids) < n:
             # 大きな範囲からランダムにID生成
             new_id = secrets.randbelow(id_space_size)
             if new_id > 0:  # IDは0以外
                 ids.add(new_id)
         return list(ids)
     ```
   - この実装により、ID から文書種別（A/B/未割当）の推測が困難になる

3. **シェア間相関の排除**：

   - チャンク間やシェア間の統計的相関を排除する手法
   - 各チャンクに対して独立したソルト値を使用
   - 実装方法：
     ```python
     def generate_chunk_shares(chunks, share_ids, p):
         """複数チャンクのシェアを生成、相関を排除"""
         all_shares = []
         for i, chunk in enumerate(chunks):
             # 各チャンク専用のソルト値を生成
             chunk_salt = secrets.token_bytes(16)
             # シェア生成時にチャンクとソルトを組み合わせ
             processed_secret = combine_with_salt(chunk, chunk_salt, p)
             # 全シェアを生成（閾値の概念は使用せず）
             polynomial_degree = len(share_ids) - 1
             chunk_shares = generate_shares(processed_secret, polynomial_degree, share_ids, p)
             all_shares.append((chunk_salt, chunk_shares))
         return all_shares
     ```
   - チャンク間の相関を排除し、統計的攻撃に対する耐性を向上

4. **チャンクサイズの厳密な統一**：

   - すべてのチャンクを 64 バイト固定サイズで処理
   - パディング実装の例：
     ```python
     def pad_chunk(chunk, target_size=64):
         """チャンクを指定サイズに厳密にパディング"""
         # チャンクサイズが小さい場合は埋める
         if len(chunk) < target_size:
             # 埋めるサイズを計算
             pad_size = target_size - len(chunk)
             # PyCryptodomeのPadding機能を使用
             from Crypto.Util.Padding import pad
             padded_chunk = pad(chunk, target_size)
             return padded_chunk
         # 既に指定サイズの場合はそのまま返す
         elif len(chunk) == target_size:
             return chunk
         # チャンクサイズが大きい場合は次のチャンクに分割（呼び出し側で処理）
         else:
             return chunk[:target_size]
     ```
   - この実装により、あらゆるチャンクが同一サイズとなり、統計的区別を不可能にする

5. **実装上のトレードオフと実用的アプローチ**：

   - 完全な統計的区別不可能性と計算効率のバランスを考慮
   - 現実的アプローチ：

     - チャンクサイズを統一（64 バイト固定）し、パディングを統一的に適用
     - HMAC-SHA を用いた決定論的なマッピング
     - 未割当領域には良質な乱数（/dev/urandom または secrets）でゴミデータを生成
     - 第 2 段階 MAP で特定された位置に有効データを配置

   - 実装例：

     ```python
     def create_secure_file(json_data, partition_key, password, salt):
         """全シェア位置に有効データを配置した安全なファイルを生成"""
         # 第1段階MAP生成
         stage1_map = generate_stage1_map(partition_key)

         # 第2段階MAP生成
         # パスワードを固定長に変換
         hashed_password = hash_to_fixed_length(password)
         stage2_map = generate_stage2_map(hashed_password, salt, stage1_map)

         # データを固定サイズチャンクに分割
         chunks = split_to_fixed_chunks(json_data, 64)

         # 必要なチャンク数と実際のチャンク数を比較
         required_chunks = len(stage2_map)
         has_enough_data = len(chunks) >= required_chunks

         # 容量が足りない場合は例外（実際の実装では定数時間処理で対応）
         if not has_enough_data:
             raise CapacityError(f"データ容量不足: 必要={required_chunks}, 実際={len(chunks)}")

         # チャンク数が多すぎる場合は切り捨て
         chunks = chunks[:required_chunks]

         # 全シェア生成
         all_shares = []
         for i, chunk in enumerate(chunks):
             # シェア生成
             shares = generate_shares_all_required(chunk, stage2_map, PRIME)
             all_shares.extend(shares)

         return all_shares
     ```

   - この実装は不足位置にゴミデータを混入せず、常に全位置を有効データで満たす

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

3. **シェア数の一貫性確保**：

   ```python
   def verify_share_count(encrypted_data, share_ids):
       """シェア数の一貫性を検証"""
       # パーティションごとに必要なシェア数を検証
       for chunk_idx, chunk_shares in enumerate(encrypted_data):
           available_shares = [s for s in chunk_shares if s[0] in share_ids]

           # 使用するシェアIDセットと一致するか確認
           if len(available_shares) != len(share_ids):
               # 不足または過剰なシェアが存在する場合は警告（エラーではない）
               log_warning(f"チャンク {chunk_idx} のシェア数が一致しません: " +
                         f"期待={len(share_ids)}, 実際={len(available_shares)}")
   ```

4. **MAPs 実装の最適化**：

   ```python
   def optimize_maps_for_all_shares(partition_key, password, salt):
       """全シェア使用方式に最適化されたMAP生成"""
       # パスワードを固定長に変換（ハッシュ化）
       normalized_password = hash_to_fixed_length(password)

       # 第1段階MAP：パーティションマップキーからシェアID全てを生成
       share_ids = generate_partition_map_ids(partition_key)

       # 第2段階MAP：固定数のシェア位置を決定
       # 正規化されたパスワードとソルトからマッピング値を生成
       mapping = {}
       key = kdf(normalized_password, salt)

       for id in share_ids:
           mapping[id] = hmac_value(key, str(id).encode())

       # 常に同じ数のシェア位置を返す
       return share_ids, mapping
   ```

5. **全シェア使用の検証と保証**：

   ```python
   def ensure_all_shares_available(shares, required_ids):
       """全シェアが利用可能か確認し、不足時はエラー処理"""
       # 必要なIDのセット
       required_set = set(required_ids)

       # 実際に利用可能なIDのセット
       available_set = set(share[0] for share in shares)

       # 不足しているIDがあるか確認
       missing_ids = required_set - available_set

       if missing_ids:
           # ここでは直接エラーを返さず、情報を返す
           # 実際の処理は呼び出し側で行う（定数時間処理の原則に従う）
           return {
               "all_available": False,
               "missing_count": len(missing_ids),
               "missing_ids": list(missing_ids)
           }

       return {
           "all_available": True,
           "shares": [s for s in shares if s[0] in required_set]
       }
   ```

6. **シェア生成時のパラメータ固定**：

   ```python
   def configure_shamir_parameters():
       """シャミアパラメータの固定設定（全シェア使用方式用）"""
       # 閾値パラメータは使用しない
       # 代わりに常に全シェアを使用するための設定

       # システム全体で固定チャンクサイズを使用
       CHUNK_SIZE = 64  # バイト

       # 全シェア使用方式の設定
       config = {
           "use_all_shares": True,  # 常に全シェアを使用
           "chunk_size": CHUNK_SIZE,  # 64バイト固定
           "polynomial_coefficients": "random",  # 多項式係数はランダム生成
           "prime_field": 2**521 - 1  # メルセンヌ素数を使用
       }

       return config
   ```

### 7.7. 容量検証と固定サイズ実装ガイドライン

以下は容量検証と固定サイズチャンクの実装に関するガイドラインです：

1. **暗号化前の容量検証**：

   ```python
   def verify_capacity_before_encryption(data, partition_key, password, salt):
       """暗号化前にデータ容量を検証"""
       # JSON文書のバイトサイズを取得
       data_size = len(data.encode('utf-8'))

       # 圧縮率を考慮した予測サイズ（保守的に0.7を使用）
       estimated_compressed_size = int(data_size * 0.7)

       # 必要チャンク数を計算（64バイト単位で切り上げ）
       required_chunks = (estimated_compressed_size + 63) // 64

       # 使用可能なシェア数はUSER_ACTIVE_SHARESで固定（定数）
       available_positions = USER_ACTIVE_SHARES

       # 容量が十分かチェック（定数時間処理）
       has_sufficient_capacity = required_chunks <= available_positions

       # 結果を返す（真偽値と必要情報）- 定数時間処理用の変数
       result = {
           "sufficient": has_sufficient_capacity,
           "required_chunks": required_chunks,
           "available_positions": available_positions,
           "max_data_size": available_positions * 64,
           "estimated_json_capacity": int(available_positions * 64 * 1.3)  # 圧縮率の逆数で戻す
       }

       # 必ず同じ処理パスを通る（定数時間処理）
       return result
   ```

2. **固定サイズデータ分割**：

   ```python
   def split_data_into_fixed_chunks(data, chunk_size=64):
       """データを固定サイズチャンクに分割"""
       # データをバイト列に変換
       if isinstance(data, str):
           data = data.encode('utf-8')

       # チャンク数を計算
       chunk_count = (len(data) + chunk_size - 1) // chunk_size

       # 固定サイズのチャンクリストを作成
       chunks = []
       for i in range(chunk_count):
           start = i * chunk_size
           end = start + chunk_size
           chunk = data[start:min(end, len(data))]

           # 最後のチャンクが不完全な場合はパディング
           if len(chunk) < chunk_size:
               # セキュアなパディング関数（実装依存）
               chunk = secure_pad(chunk, chunk_size)

           chunks.append(chunk)

       return chunks
   ```

3. **パスワードの固定長変換**：

   ```python
   def hash_to_fixed_length(password, output_length=32):
       """パスワードを固定長に変換（UTF-8対応）"""
       # 特定のハッシュアルゴリズムを使用
       # SHA-256は32バイト（256ビット）の出力を生成
       import hashlib
       import unicodedata

       # Unicode正規化（NFC形式）を適用
       # 例：分解された「é」(e + ´) と合成された「é」を同一に扱う
       if isinstance(password, str):
           normalized_password = unicodedata.normalize('NFC', password)
           password_bytes = normalized_password.encode('utf-8')
       else:
           password_bytes = password

       hash_obj = hashlib.sha256(password_bytes)
       return hash_obj.digest()
   ```

4. **MAP 生成の固定サイズ保証**：

   ```python
   def generate_fixed_size_map(password, partition_key, salt, target_size=None):
       """固定サイズのMAPを生成"""
       # パスワードを固定長ハッシュに変換
       pwd_hash = hash_to_fixed_length(password)

       # パーティションマップキーからベースとなるIDのセットを取得（USER_PARTITION_SIZE個）
       base_ids = generate_partition_map_ids(partition_key)

       # target_sizeが指定されていない場合は定数値USER_ACTIVE_SHARESを使用
       if target_size is None:
           target_size = USER_ACTIVE_SHARES

       # KDFを使用して派生キーを生成
       derived_key = secure_kdf(pwd_hash, salt, iterations=310000)

       # 必要なシェア位置数を確保（常に固定サイズUSER_ACTIVE_SHARES個）
       map_positions = []

       # パーティション内で分散させながらUSER_ACTIVE_SHARES個の位置を決定論的に選択
       # パスワードから導出された派生キーをもとに決定する
       for i in range(target_size):
           # 決定論的に位置を選択（パスワードに基づく決定論的マッピング）
           index = derive_secure_index(derived_key, i, len(base_ids))
           position = base_ids[index]
           map_positions.append(position)

       return map_positions
   ```

5. **固定長シリアライズ処理**：

   ```python
   def fixed_length_serialize(data, fixed_field_sizes=None):
       """データを固定長形式でシリアライズ"""
       if fixed_field_sizes is None:
           # デフォルトのフィールドサイズ設定
           fixed_field_sizes = {
               "share_id": 10,     # シェアIDの固定文字数
               "share_value": 128, # シェア値の固定文字数
               "salt": 64          # ソルト値の固定文字数
           }

       # シェアIDの固定長シリアライズ
       share_id_str = str(data["id"]).zfill(fixed_field_sizes["share_id"])
       if len(share_id_str) > fixed_field_sizes["share_id"]:
           share_id_str = share_id_str[-fixed_field_sizes["share_id"]:]

       # シェア値の固定長シリアライズ（16進数表現）
       share_value_hex = format(data["value"], 'x')
       share_value_str = share_value_hex.zfill(fixed_field_sizes["share_value"])
       if len(share_value_str) > fixed_field_sizes["share_value"]:
           share_value_str = share_value_str[-fixed_field_sizes["share_value"]:]

       # 固定長形式で結合
       return share_id_str + share_value_str
   ```

これらのガイドラインを実装することで、固定サイズチャンクと容量制限を適切に処理し、セキュリティを確保しながら効率的な実装が可能になります。

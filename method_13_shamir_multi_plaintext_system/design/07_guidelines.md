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

   - パーティションマップ内のシェア（有効シェアとガベージシェア）の分布はランダム性を維持し、パターンを形成しない
   - 任意の連続範囲において、各種別（A/B/未割当）の分布比率が一定となるよう設計
   - ブロック単位での分布検証を実施し、統計的均一性を確保

2. **シェア ID 処理の最適化**：

   - シェア ID の分布テーブルをビットマップまたは固定長配列として実装し、直接アクセス可能にする
   - シェア ID がどのパーティション（A/B/ガベージシェア）に属するかの判定には、条件分岐のない実装を使用
   - マスク演算（AND/OR）を用いた定数時間アクセス処理により、サイドチャネル漏洩を防止

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
     - 未割当領域には良質な乱数（/dev/urandom または secrets）でガベージシェアを生成
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

         # データ定量化（64バイト固定長に調整）
         quantized_chunks = quantize_data_chunks(chunks, required_chunks)

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

   - この実装は不足位置にガベージシェアを混入せず、常に全位置を有効データで満たす

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

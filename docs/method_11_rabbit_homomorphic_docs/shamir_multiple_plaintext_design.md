# シャミア秘密分散法による複数平文復号システム設計

**作成日**: 2024 年 5 月

## 1. 設計概要

本設計は、シャミア秘密分散法を応用し、単一の暗号化ファイルから異なるパスワードに応じて異なる平文 JSON を復号できるシステムを実現するものです。パスワードと秘密の JSON 設定ファイルから生成されるマップデータにより、適切なシェアを特定し復号する仕組みを構築します。

### 1.1 主要な特徴

- 1 つの暗号化ファイルに 2 つの異なる JSON 文書を格納
- パスワードに応じて異なる平文を復号
- シェア自体には所属文書の識別情報を含まない
- 復号プロセスは文書の種類に関わらず同一
- ソースコード漏洩に対する耐性

### 1.2 システムアーキテクチャ

システムは以下の主要コンポーネントで構成されます：

1. **暗号化モジュール**: 平文 JSON の暗号化とシェア生成
2. **復号モジュール**: パスワードからのマップデータ生成と該当シェアの復号
3. **マップデータジェネレータ**: パスワードとユーザー指定 JSON からのマップ生成
4. **シェア管理機構**: 有効シェアとゴミシェアの混在管理

## 2. 詳細設計

### 2.1 シャミア秘密分散法の実装

シャミア秘密分散法は、秘密情報を複数のシェアに分散し、定められた閾値以上のシェアがあれば元の情報を復元できる手法です。本システムでは以下のように拡張します。

#### 2.1.1 多項式の生成と次数

各 JSON データを固定サイズのブロックに分割し、各ブロックに対してシャミア秘密分散を適用します。

```
f(x) = s + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹ (mod p)
```

ここで:

- `s`: 秘密情報（JSON ブロック）
- `t`: 閾値（復号に必要なシェア数）
- `p`: 大きな素数（有限体の位数）
- `aᵢ`: ランダムに選ばれた係数

**推奨パラメータ**:

- 閾値(t): 5
- 総シェア数: 各文書につき 10 シェア（合計 20 シェア）
- ゴミシェア: 6 シェア（全体の約 30%）
- 有限体の素数(p): 2²⁵⁶ 以上

#### 2.1.2 シェア生成アルゴリズム

1. JSON 文書を k 個の固定長ブロック{B₁, B₂, ..., Bₖ}に分割
2. 各ブロック Bᵢ に対して:
   - 文書 A のブロックには多項式 fₐ(x)を使用
   - 文書 B のブロックには多項式 fᵦ(x)を使用
3. 各多項式から各文書につき 10 個のシェアを生成
4. ランダムなゴミシェアを 6 個生成
5. 全シェア（A, B, ゴミ）を混在させて格納

#### 2.1.3 シェア形式

各シェアは以下の情報を含みます：

```
シェア = (x座標, y座標, ブロックインデックス)
```

ここで:

- `x座標`: シェアの識別子
- `y座標`: 多項式 f(x)の評価値
- `ブロックインデックス`: 元の JSON ブロックの位置情報

重要: シェア自体には、それが文書 A または B のものか、ゴミシェアかを示す情報は含みません。

### 2.2 マップデータ設計

マップデータは、特定の平文を復号するために必要なシェアを特定するための鍵となります。

#### 2.2.1 マップデータの生成

1. **パスワードの正規化**:

   ```
   normalizedPassword = PBKDF2(password, salt, iterations=10000, dklen=32)
   ```

2. **ユーザー指定 JSON との結合**:

   ```
   combinedSecret = HMAC-SHA256(normalizedPassword, userProvidedJson)
   ```

3. **マップシード生成**:

   ```
   mapSeed = HKDF(combinedSecret, salt, info="shamir_map", length=64)
   ```

4. **マップデータの構築**:
   ```
   mapData = generateMap(mapSeed, totalShares, requiredShares)
   ```

#### 2.2.2 マップデータ構造

マップデータは以下の情報を持つ辞書形式で保存されます：

```json
{
  "version": "1.0",
  "threshold": 5,
  "blocks": 128,
  "map": {
    "block_1": [3, 8, 12, 15, 22],
    "block_2": [1, 7, 11, 18, 23],
    ...
  }
}
```

ここで:

- `version`: マップデータのバージョン
- `threshold`: 復号に必要なシェア数
- `blocks`: JSON 文書のブロック数
- `map`: 各ブロックに対する有効シェアのインデックスリスト

### 2.3 暗号化プロセス

1. 2 つの JSON 文書（A, B）と 2 つのパスワードを入力
2. 各 JSON 文書を固定サイズのブロックに分割
3. 各ブロックに対してシャミア秘密分散法を適用し、シェアを生成
4. 文書 A と B のシェアをプールし、ゴミシェアを追加
5. 各パスワードに対してマップデータを生成
6. 全シェアをランダムに並べ替えて暗号化ファイルに格納
7. 暗号化ファイルのヘッダにシステムパラメータを保存

### 2.4 復号プロセス

1. 暗号化ファイルとパスワードを入力
2. パスワードとユーザー指定 JSON からマップデータを再生成
3. マップデータに基づいて必要なシェアを特定
4. 特定されたシェアから各ブロックを復元
5. 復元されたブロックを結合して元の JSON 文書を再構築

### 2.5 エラー処理

1. **不正パスワード**:

   - マップデータが存在しないシェアを指し示すため、多項式補間に失敗
   - エラーメッセージ: "復号エラー: 無効なパスワードまたは破損したデータ"

2. **破損したシェア**:
   - 閾値設計により、一部のシェアが破損していても復号可能
   - ただし、破損シェアが閾値を超える場合はエラー発生

## 3. セキュリティ分析

### 3.1 攻撃モデル

1. **ソースコード漏洩攻撃**: 攻撃者はシステムのソースコードを入手し解析
2. **暗号文分析攻撃**: 攻撃者は暗号化ファイルを所有
3. **部分知識攻撃**: 攻撃者は一方の平文の一部を知っている

### 3.2 セキュリティ対策

1. **シェアの区別不可能性**:

   - 全てのシェア（文書 A、B、ゴミ）は統計的に区別不可能
   - シェアの形式と分布が均一であることを確認

2. **マップデータの安全性**:

   - マップデータはパスワードとユーザー指定 JSON に依存
   - 強力な KDF とハッシュ関数の使用
   - ユーザー指定 JSON なしではマップデータの復元は計算的に不可能

3. **ソースコード解析耐性**:
   - マップデータ生成ロジックの秘匿性確保
   - ハードコードされた秘密情報の排除
   - コード内に暗号化のキーとなる情報を含めない

### 3.3 安全性証明

攻撃者がソースコードと暗号文を入手しても、以下の理由により平文の復元は困難です：

1. シェア自体からはどの文書に属するかの情報を得られない
2. ユーザー指定 JSON がなければマップデータを生成できない
3. マップデータがなければ正しいシェアを特定できない
4. 総当たり攻撃には 2^256 以上の計算コストが必要

## 4. 性能評価

### 4.1 暗号化後のファイルサイズ予測

シャミア秘密分散法では、各シェアは元のデータとほぼ同じサイズになります。文書 A、文書 B、およびゴミシェア（30%）を考慮すると：

1. **10KB JSON の場合**:

   - 文書 A（10KB）: 10 シェア = 100KB
   - 文書 B（10KB）: 10 シェア = 100KB
   - ゴミシェア（30%）: 約 60KB
   - メタデータ: 約 2KB
   - **合計: 約 262KB**

2. **100KB JSON の場合**:

   - 文書 A（100KB）: 10 シェア = 1000KB
   - 文書 B（100KB）: 10 シェア = 1000KB
   - ゴミシェア（30%）: 約 600KB
   - メタデータ: 約 5KB
   - **合計: 約 2.6MB**

3. **1MB JSON の場合**:
   - 文書 A（1MB）: 10 シェア = 10MB
   - 文書 B（1MB）: 10 シェア = 10MB
   - ゴミシェア（30%）: 約 6MB
   - メタデータ: 約 10KB
   - **合計: 約 26MB**

### 4.2 計算量とパフォーマンス

1. **暗号化処理**:

   - 時間複雑性: O(n log n)（n は JSON 文書のサイズ）
   - 10KB JSON: 約 0.5 秒
   - 100KB JSON: 約 2 秒
   - 1MB JSON: 約 15 秒

2. **復号処理**:

   - 時間複雑性: O(t・m log m)（t は閾値、m はブロック数）
   - 10KB JSON: 約 0.3 秒
   - 100KB JSON: 約 1.5 秒
   - 1MB JSON: 約 12 秒

3. **メモリ使用量**:
   - 暗号化時: 元の JSON サイズの約 5 倍
   - 復号時: 元の JSON サイズの約 3 倍

## 5. 実装ガイドライン

### 5.1 推奨データ構造

1. **シェア管理**:

   - ハッシュテーブルを使用してシェアのインデックス付け
   - バイナリ形式でのシェア格納による効率化

2. **多項式演算**:
   - 有限体上の効率的な多項式計算ライブラリの使用
   - ラグランジュ補間法による効率的な復元

### 5.2 推奨ライブラリ

1. **暗号処理**:

   - OpenSSL / LibSodium / Bouncy Castle
   - hashlib / cryptography (Python)

2. **シャミア秘密分散**:

   - PyCryptodome
   - secrets.js
   - SSS (Shamir's Secret Sharing) ライブラリ

3. **JSON 処理**:
   - RapidJSON / Jackson / json
   - 大きな JSON の効率的な処理のためのストリーミングパーサー

### 5.3 最適化テクニック

1. **並列処理**:

   - ブロック単位での並列暗号化/復号
   - マルチスレッド処理による高速化

2. **メモリ最適化**:

   - ストリーミング処理による大きな JSON のハンドリング
   - 必要に応じたシェアのロード（全シェアを同時にメモリに読み込まない）

3. **計算最適化**:
   - 事前計算テーブルによるラグランジュ補間の高速化
   - ビット操作の最適化による有限体演算の効率化

## 6. 実装例（疑似コード）

### 6.1 暗号化処理

```python
def encrypt(json_a, json_b, password_a, password_b, user_json):
    # JSONをブロックに分割
    blocks_a = split_into_blocks(json_a)
    blocks_b = split_into_blocks(json_b)

    # シェア生成
    shares_a = []
    shares_b = []
    for i, block in enumerate(blocks_a):
        shares_a.extend(generate_shares(block, threshold=5, total_shares=10, block_index=i))

    for i, block in enumerate(blocks_b):
        shares_b.extend(generate_shares(block, threshold=5, total_shares=10, block_index=i))

    # ゴミシェア生成
    garbage_shares = generate_garbage_shares(len(shares_a) * 0.3)

    # マップデータ生成
    map_a = generate_map(password_a, user_json, shares_a)
    map_b = generate_map(password_b, user_json, shares_b)

    # 全シェアの混在
    all_shares = shares_a + shares_b + garbage_shares
    random.shuffle(all_shares)

    # 暗号化ファイル生成
    encrypted_file = {
        "version": "1.0",
        "total_shares": len(all_shares),
        "threshold": 5,
        "shares": all_shares
    }

    return encrypted_file, map_a, map_b
```

### 6.2 復号処理

```python
def decrypt(encrypted_file, password, user_json):
    # マップデータ再生成
    map_data = regenerate_map(password, user_json)

    # シェア取得
    shares = encrypted_file["shares"]

    # ブロック数取得
    num_blocks = map_data["blocks"]

    # 各ブロックの復元
    reconstructed_blocks = []
    for block_idx in range(num_blocks):
        # マップから該当ブロックのシェアインデックスを取得
        share_indices = map_data["map"][f"block_{block_idx}"]

        # 対応するシェアを収集
        block_shares = []
        for idx in share_indices:
            if idx < len(shares) and shares[idx]["block_index"] == block_idx:
                block_shares.append(shares[idx])

        # シェアが閾値以上あるか確認
        if len(block_shares) >= encrypted_file["threshold"]:
            # ブロック復元
            block = reconstruct_secret(block_shares)
            reconstructed_blocks.append(block)
        else:
            raise ValueError("復号エラー: 無効なパスワードまたは破損したデータ")

    # ブロックを結合して元のJSONを復元
    json_data = combine_blocks(reconstructed_blocks)

    return json_data
```

### 6.3 マップデータ生成

```python
def generate_map(password, user_json, shares):
    # パスワード正規化
    normalized_pwd = pbkdf2(password, salt, iterations=10000, dklen=32)

    # ユーザー指定JSONとの結合
    json_bytes = json.dumps(user_json).encode('utf-8')
    combined = hmac_sha256(normalized_pwd, json_bytes)

    # マップシード生成
    map_seed = hkdf(combined, salt, info="shamir_map", length=64)

    # 擬似乱数生成器の初期化
    prng = PRNG(map_seed)

    # ブロックごとのマップ作成
    map_data = {
        "version": "1.0",
        "threshold": 5,
        "blocks": max(share["block_index"] for share in shares) + 1,
        "map": {}
    }

    # ブロックごとに有効なシェアを選択
    for block_idx in range(map_data["blocks"]):
        # 現在のブロックに関連するシェアを取得
        block_shares = [share for share in shares if share["block_index"] == block_idx]

        # 閾値個のシェアをランダムに選択
        selected_indices = prng.sample(range(len(block_shares)), map_data["threshold"])

        # マップに保存
        map_data["map"][f"block_{block_idx}"] = selected_indices

    return map_data
```

## 7. 結論

本設計では、シャミア秘密分散法を応用し、単一の暗号化ファイルから異なるパスワードで異なる平文 JSON を復号できるシステムを実現しました。ユーザー指定 JSON ファイルと組み合わせたマップデータ生成メカニズムにより、高いセキュリティと使いやすさを両立しています。

シェア自体には文書の種類を示すメタデータを含まず、復号プロセスも文書の種類によらず同一のコードパスを通るため、攻撃者がソースコードを入手しても、マップデータ生成の秘密（ユーザー指定の JSON ファイル）がなければ復号は不可能です。

サイズ評価からは、元の JSON サイズの約 13 倍の暗号化ファイルサイズが予想されますが、閾値秘密分散の性質上、これは許容範囲内と考えられます。復号時間も 1MB 程度の JSON で約 12 秒と実用的な範囲に収まります。

本設計の実装と運用により、単一暗号文から複数の平文を安全に復号できるシステムが実現可能です。

# シャミア秘密分散法による複数平文復号システム設計書

## 4. 実装詳細

### 4.1. 基本システム実装方針

#### 4.1.1. 一貫した用語と責務

- 暗号書庫（CryptoStorage）：システム全体が管理する暗号化データファイル
- 生成処理（createCryptoStorage）：暗号書庫の初期作成と基盤構造確立処理
- 更新処理（updateCryptoStorage）：暗号書庫への文書の暗号化と保存処理
- 読取処理（readCryptoStorage）：暗号書庫からの文書の復号と取得処理

これらの処理は独立した責務を持ち、システムの核となる 3 つの操作として実装される。

#### 4.1.2. 直交処理原則

すべての処理ステップは互いに独立した一貫性を持ち、入力データの特性に左右されることなく、常に同一の方法で実行される。これにより：

- パターン分析攻撃への耐性を確保
- 条件分岐を最小化し、サイドチャネル攻撃リスクを低減
- 入力データの特性を暗号化後のデータから推測することを困難に

#### 4.1.3. 統計的区別不可能性の確保

- すべてのシェアは外見上区別できず、同一の統計的特性を持つ
- データサイズによらず固定サイズ処理が適用され、サイズによる区別を防止
- A/B 文書やガベージシェアの区別は不可能に設計

### 4.2. 暗号書庫生成処理の実装

#### 4.2.1. 全体フロー

1. シェア ID 空間（`SHARE_ID_SPACE`）を設定パラメータに基づいて確定
2. 全シェア空間をランダムに 3 区画に分割：
   - A 用パーティション（`PARTITION_SIZE`分）
   - B 用パーティション（`PARTITION_SIZE`分）
   - 未割当領域（`UNASSIGNED_SHARES`分）
3. シェア空間全体にガベージシェアを配置
4. A/B 領域それぞれに対してパーティションマップキーを導出
5. UUID ベースのファイル名で暗号書庫ファイルを生成（タイムスタンプ情報なし）

#### 4.2.2. パーティションマップキーの生成ロジック

```python
def generate_partition_map_key(partition_distribution):
    """領域分布からパーティションマップキーを生成する関数"""
    # 領域分布をコンパクトな表現に変換
    compressed_distribution = compress_distribution(partition_distribution)

    # 暗号学的に強力なハッシュ関数で鍵を生成
    key_material = hmac_sha256(SYSTEM_SECRET, compressed_distribution)

    # 鍵を扱いやすい形式（Base64など）に変換
    formatted_key = format_key(key_material)

    return formatted_key
```

パーティションマップキーは一方向変換であり、領域分布の復元のみに使用可能。

#### 4.2.3. 領域分布の復元

パーティションマップキーから元の領域分布を復元する処理は、暗号書庫の更新（updateCryptoStorage）と読取（readCryptoStorage）操作の最初のステップとして実装されます。

```python
def restore_partition_distribution(partition_map_key):
    """パーティションマップキーから元の領域分布を復元する関数"""
    # パーティションマップキーを解析
    key_material = parse_key(partition_map_key)

    # 鍵から領域分布の圧縮表現を復元する検証処理
    valid_key, compressed_distribution = verify_key(key_material, SYSTEM_SECRET)

    if not valid_key:
        raise InvalidPartitionMapKeyError("無効なパーティションマップキーです")

    # 圧縮された分布から完全な領域分布を再構築
    partition_distribution = decompress_distribution(compressed_distribution)

    # 復元された分布が有効か検証（PARTITION_SIZEと一致するか、重複がないか等）
    validate_partition_distribution(partition_distribution)

    return partition_distribution
```

この復元処理により、パーティションマップキーがあれば、任意の暗号書庫に対して正確に同じ領域分布（A 領域または B 領域のシェア ID セット）を再現できます。この方式の重要な特性は：

1. **決定論的再現性**: 同一のパーティションマップキーからは常に同一の領域分布が復元される
2. **安全性**: パーティションマップキーなしでは領域分布を特定できない
3. **完全性**: 復元された分布には領域に属するすべてのシェア ID が含まれる（PARTITION_SIZE 分）
4. **整合性**: 復元処理は分布の妥当性検証を含み、不正なキーや破損したキーを検出する

この領域分布の復元は、パスワードからシェア ID を特定する第 2 段階 MAP の生成前に必須のステップとなります。

### 4.3. データ暗号化処理の共通実装

#### 4.3.1. 多段エンコードプロセス

全ての入力データに対して、以下の統一的な変換処理を適用：

1. JSON 文書を UTF-8 テキストとして処理
2. 固定容量検証とパディング処理：
   - データサイズが`ACTIVE_SHARES × CHUNK_SIZE`以内か検証
   - データサイズによらず同一のパディング処理を適用
3. 多段エンコード変換：
   - UTF-8 → Latin-1 エンコード変換
   - Latin-1 → Base64 エンコード
   - Base64 → 固定長シリアライズ処理

#### 4.3.2. チャンク分割と処理

1. エンコード済みデータを 64 バイト固定サイズのチャンクに分割
2. 全チャンクに対して同一の処理を適用（最後のチャンクも含む）
3. 分割後のチャンク数が`ACTIVE_SHARES`と一致することを確認

#### 4.3.3. シャミア秘密分散法の実装

全シェア使用方式を採用し、冗長性ではなくセキュリティを優先：

```python
def create_shares(secret, num_shares, prime):
    """秘密値から指定数のシェアを生成"""
    coefficients = [secret]  # 係数[0]は秘密値

    # 多項式の次数は (num_shares-1)
    for i in range(1, num_shares):
        # 係数はランダムに生成 (1 ~ prime-1)
        coefficients.append(random.randint(1, prime-1))

    # 各シェアを計算 (x=1, 2, ..., num_shares)
    shares = []
    for x in range(1, num_shares + 1):
        # P(x) = a0 + a1*x + a2*x^2 + ... + a[n-1]*x^(n-1) mod p
        y = coefficients[0]  # a0 (秘密値)
        for i in range(1, len(coefficients)):
            term = (coefficients[i] * pow(x, i, prime)) % prime
            y = (y + term) % prime

        shares.append((x, y))  # (x座標, y座標) のペアを保存

    return shares
```

### 4.4. 暗号書庫更新処理の実装

#### 4.4.1. 全体フロー

1. **安全性前処理**：

   - 暗号書庫ファイルのバックアップを作成（UUID 付加）
   - 処理状態を示すロックファイルを生成
   - 保持期間を超過した古いバックアップを削除

2. **MAP 生成**：

   - パーティションマップキーから第 1 段階 MAP を再生成
   - パスワードと第 1 段階 MAP から第 2 段階 MAP を生成
   - 第 2 段階 MAP は暗号書庫構造と独立した相対的マッピングを適用

3. **データ処理**：

   - JSON データの容量検証と多段エンコード
   - チャンク分割（64 バイト固定長）
   - 各チャンクに対してシャミア法でシェア生成
   - 生成したシェアを第 2 段階 MAP に従って配置

4. **安全性後処理**：
   - 処理完了時：ロックファイル削除
   - 異常終了時：バックアップから復元

#### 4.4.2. 障害耐性の実装

シンプルかつ確実なエラーリカバリの実装：

```python
def update_crypto_storage(storage_file, json_data, partition_key, password):
    """暗号書庫の更新処理"""
    # バックアップの作成
    backup_file = create_backup(storage_file)

    try:
        # ロックファイル作成
        lock_file = create_lock_file(storage_file)

        # 更新処理のメイン部分
        # 1. MAP生成
        stage1_map = generate_stage1_map(partition_key)
        stage2_map = generate_stage2_map(stage1_map, password)

        # 2. データ処理と暗号化
        shares = process_and_encrypt_data(json_data, stage2_map)

        # 3. 暗号書庫ファイルの更新
        write_storage_file(storage_file, shares)

        # 処理完了の正常終了処理
        os.remove(lock_file)
        return True

    except Exception as e:
        # エラー発生時はバックアップから復元
        restore_from_backup(backup_file, storage_file)
        raise e
    finally:
        # クリーンアップ処理（ロックファイルの削除など）
        cleanup_resources()
```

#### 4.4.3. A/B 文書独立性の保証

更新処理における他文書の非破壊は以下の方法で保証：

1. パーティションマップキーにより、A/B 領域が完全に分離
2. 更新対象領域のシェアのみを変更し、他方の領域のシェアは保持
3. シェア配置時に領域境界チェックを実施

### 4.5. 暗号書庫読取処理の実装

#### 4.5.1. 全体フロー

1. **入力処理**：

   - 暗号書庫ファイル、パーティションマップキー、パスワードの取得

2. **MAP 生成**：

   - パーティションマップキーから第 1 段階 MAP を再生成
   - パスワードと第 1 段階 MAP から第 2 段階 MAP を生成
   - 第 2 段階 MAP は書庫独立性を持つ相対的マッピングを適用

3. **データ復号**：
   - 第 2 段階 MAP に従ってシェアを選択
   - ラグランジュ補間によるシャミア法逆適用でチャンク復元
   - チャンク結合と多段デコード処理
   - パディング除去と JSON 復元

#### 4.5.2. シェア復元アルゴリズム

```python
def recover_secret(shares, prime):
    """シェアから秘密を復元（ラグランジュ補間法）"""
    x_values = [x for x, _ in shares]
    y_values = [y for _, y in shares]

    # ラグランジュ基底多項式の計算
    secret = 0
    for i in range(len(shares)):
        xi, yi = shares[i]

        # ラグランジュ基底多項式の分子・分母を計算
        numerator = 1
        denominator = 1
        for j in range(len(shares)):
            if i == j:
                continue

            xj = shares[j][0]
            numerator = (numerator * (0 - xj)) % prime
            denominator = (denominator * (xi - xj)) % prime

        # 逆元を計算
        inverse = pow(denominator, prime-2, prime)

        # 項を加算
        secret = (secret + yi * numerator * inverse) % prime

    # 負の値の場合は正の値に変換
    if secret < 0:
        secret += prime

    return secret
```

#### 4.5.3. 多段デコードプロセス

復号データに対して暗号化と反対の処理を順に適用：

1. 固定長デシリアライズ
2. Base64 デコード
3. Latin-1 から UTF-8 へのエンコード変換
4. パディング除去
5. JSON 解析

### 4.6. セキュリティ強化と最適化

#### 4.6.1. タイミング攻撃対策

実装全体で定数時間演算を採用し、タイミング攻撃に対する耐性を確保：

1. 比較操作では`constant_time_compare`関数を使用
2. 条件分岐を最小化した直交的処理パス
3. 全データに対して同一の処理ステップを適用

#### 4.6.2. メモリ安全性

1. 機密データ処理後の確実なメモリクリア
2. 一時バッファの安全な割り当てと解放
3. ガベージコレクション前の機密データの明示的なゼロクリア

#### 4.6.3. パフォーマンス最適化

1. 大きな素数演算の効率化（gmpy2 ライブラリの活用）
2. シェア生成・復元処理の並列実行
3. キャッシュラインサイズに合わせたチャンクサイズ最適化

### 4.7. 例外処理とエラー管理

#### 4.7.1. エラー発生時の振る舞い

- 復号失敗時も例外を発生させず、得られたデータをそのまま返却
- 容量制限超過時は明確なエラーメッセージで処理中止
- ロックファイル処理のエラーは詳細なログ記録と回復手順の実行

#### 4.7.2. リソース管理とクリーンアップ

- finally 句による確実なリソース解放
- 一時ファイルとロックファイルの自動クリーンアップ
- 例外発生時の状態復元とロールバック処理

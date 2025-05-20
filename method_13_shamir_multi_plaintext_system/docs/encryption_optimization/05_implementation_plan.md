# 実装計画と優先順位

## 設計書への準拠を確保する実装手順

設計書の「多段 MAP 方式」と「ファイルパーティション設計」に厳密に準拠するため、以下の順序で実装します：

1. **セキュリティ準拠の新形式実装** - 設計書に完全準拠した新しいファイル形式を実装（過去形式との互換性は一切考慮しない）
2. **初期化時の暗号化ファイル生成** - 全シェア ID（`SHARE_ID_SPACE = PARTITION_SIZE * 2 + UNASSIGNED_SHARES`個）をガベージシェアで埋めた暗号化ファイルを初期化時に自動生成し、UUID による一意な命名を実装
3. **完全固定長シリアライズの実装** - 全てのシェア値を厳密に固定長（`FIXED_VALUE_LENGTH`バイト、`constants.py`で定義）でシリアライズし、統計的区別不可能性を確保
4. **多段 MAP 方式の完全実装** - パーティションマップキーによる「第 1 段階 MAP」とパスワードによる「第 2 段階 MAP」の連携実装
5. **過去形式関連コードの完全削除** - セキュリティリスクとなる過去形式に関連するコードを完全に削除し、コードベースを浄化
6. **進捗表示機能の実装** - 長時間処理の視覚的フィードバックを提供し、ユーザー体験を向上

## 過去形式関連コードの完全削除

セキュリティリスクを排除するため、過去形式に関連するコードとその関数は**コードベース内に一切残さない**こととします：

- **削除対象関数の例**:

  - `create_v1_format()`
  - `create_v2_format()`
  - `read_v1_format()`
  - `read_v2_format()`
  - `convert_v1_to_v2()`
  - `is_v1_format()`
  - `is_v2_format()`
  - その他、過去形式に関連するすべてのヘルパー関数

- **新しい形式のみの実装**:
  - 新たに`create_encrypted_format()`、`read_encrypted_format()`などの関数のみを実装
  - 変換関数も一切実装しない
  - 過去形式ファイルに対しては明確なエラーメッセージを表示し、変換は行わない
  - 変換機能を要求するユーザーには別途移行手順を案内

過去形式関連コードの一切が残っていないことを確認するため、次のコードレビュー手順を実施します：

```python
# 実装後のコードレビューで確認すべき項目
def code_review_remove_old_formats():
    """
    過去形式に関連するコードが完全に削除されていることを確認する
    """
    # 1. 過去形式の関数が存在しないことを確認
    assert not hasattr(module, "create_v1_format")
    assert not hasattr(module, "create_v2_format")
    assert not hasattr(module, "read_v1_format")
    assert not hasattr(module, "read_v2_format")

    # 2. 過去形式への変換関数が存在しないことを確認
    assert not hasattr(module, "convert_v1_to_v2")
    assert not hasattr(module, "convert_format")

    # 3. インポート文やコメントにも過去形式への言及がないことを確認
    source_code = inspect.getsource(module)
    assert "v1_format" not in source_code
    assert "v2_format" not in source_code

    # 4. 過去形式の識別コードが存在しないことを確認
    assert not hasattr(module, "is_v1_format")
    assert not hasattr(module, "is_v2_format")

    print("成功: すべての過去形式関連コードが完全に削除されています")
```

これにより、コードベース内に過去形式のコードが一切残らず、セキュリティリスクのある実装が混入する可能性を排除します。

## 最小限のヘッダー情報

設計書の「メタデータの極小化」原則に従い、シェアフォーマットにおいては必要最小限のヘッダー情報のみを保持します：

1. **salt**: シェア生成に使用したソルト値（Base64 エンコード）

以下のメタデータは不要であり、セキュリティリスクとなるため含めません：

- **magic**: 固定値は暗号ファイルの特性を示す手がかりになるため削除
- **created_at**: 作成時刻はファイル解析の手がかりとなるリスクがある
- **share_id_space**: 配列のサイズから計算可能
- **total_chunks**: 多段 MAP 方式から導出可能なため冗長
- **threshold**: 本システムでは閾値の概念は使用せず、常に全シェア（`ACTIVE_SHARES`個）を使用
- **file_type**: ファイル種別（A/B）はパーティションマップキーから導出可能なため不要
- **version**: 互換性は別の方法で処理するため不要

## 詳細実装手順

### ステップ 1: セキュリティ準拠の新形式実装

1. パーティション設計パラメータを`constants.py`に定義

   ```python
   # ファイルパーティション設計
   ACTIVE_SHARES = 2000    # 各ファイル(A/B)用有効シェア数（整数、共通値）
   GARBAGE_SHARES = 2000   # 各ファイル(A/B)用ガベージシェア数（整数、共通値）
   PARTITION_SIZE = ACTIVE_SHARES + GARBAGE_SHARES  # 各ファイル(A/B)用パーティション総サイズ（自動計算）

   # 未割当領域
   UNASSIGNED_SHARES = 4000     # 未割当シェア数（整数）ガベージシェア

   # 全体シェア数（自動計算）
   SHARE_ID_SPACE = PARTITION_SIZE * 2 + UNASSIGNED_SHARES

   # シェア値の固定長シリアライズサイズ（バイト）
   FIXED_VALUE_LENGTH = 256
   ```

2. `create_encrypted_format()` 関数を作成し、新しい形式の暗号化ファイルを新規作成する機能を実装

   ```python
   def create_encrypted_format(shares, salt):
       """
       新しい暗号化ファイル形式を作成する

       Args:
           shares: シェア辞書 {シェアID: シェア値}
           salt: ソルト値

       Returns:
           シリアライズされた暗号化ファイルデータ
       """
       # 最小限のヘッダー情報（ソルト値のみ）
       header = {
           "salt": base64.b64encode(salt).decode('ascii')
       }

       # 全てのシェアを固定長でシリアライズ
       serialized_shares = []
       for share_id in range(1, SHARE_ID_SPACE + 1):
           if share_id in shares:
               # 既存のシェア値を使用
               value = shares[share_id]
           else:
               # ガベージシェア値を生成
               value = generate_garbage_share_value()

           # シェア値を固定長でシリアライズ
           serialized_value = fixed_length_serialize(value, FIXED_VALUE_LENGTH)
           serialized_shares.append(serialized_value)

       # JSONとして全体をシリアライズ
       data = {
           "header": header,
           "shares": serialized_shares
       }

       return json.dumps(data)
   ```

3. `get_share_index()` 関数を作成し、多段 MAP 方式から一次元配列内の位置を算出
4. `fixed_length_serialize()` 関数を作成し、完全固定長シリアライズを実装

   ```python
   def fixed_length_serialize(value, length=FIXED_VALUE_LENGTH):
       """
       値を固定長にシリアライズする

       Args:
           value: シリアライズする値
           length: 固定長（バイト数）

       Returns:
           固定長にシリアライズされた値
       """
       # 値を16進数文字列に変換
       hex_value = format(value, 'x')

       # 固定長に調整
       if len(hex_value) < length * 2:  # 16進数では1バイト=2文字
           # 左側にゼロパディング
           serialized = hex_value.zfill(length * 2)
       else:
           # 固定長に切り詰め
           serialized = hex_value[-(length * 2):]

       return serialized
   ```

5. 過去形式関連の全コードを完全に削除
6. **【実装禁止事項】** 以下の機能は直交処理原則に反するため、実装しません：
   - 過去形式のファイルに対するエラーハンドリング機能
   - 新しい形式のみをサポートする形式判定やエラーメッセージ表示機能
   - 任意の形式判定や特定のエラー表示（これらは判定や評価が必要となるため）

### ステップ 2: 初期化時の暗号化ファイル生成

1. `generate_empty_encrypted_file()` 関数を実装

   ```python
   def generate_empty_encrypted_file(output_path=None):
       """
       初期化時に全シェアIDをガベージシェアで埋めた暗号化ファイルを生成

       Args:
           output_path: 出力ファイルパス（Noneの場合は自動生成）

       Returns:
           生成したファイルパス
       """
       # 新しいUUIDを生成
       file_uuid = uuid.uuid4()

       # 出力パスが指定されていない場合は自動生成
       if output_path is None:
           output_path = f"encrypted_{file_uuid}.henc"

       # ソルト値を生成
       salt = os.urandom(32)

       # 全シェアをガベージシェアで埋める
       shares = {}
       for share_id in range(1, SHARE_ID_SPACE + 1):
           shares[share_id] = generate_garbage_share_value()

       # 暗号化ファイルを作成
       encrypted_data = create_encrypted_format(shares, salt)

       # ファイルに書き込み
       with open(output_path, 'w') as f:
           f.write(encrypted_data)

       return output_path
   ```

2. `init` コマンドにこの機能を統合
3. パーティションマップキーの生成と暗号化ファイル生成を連携

   ```python
   def generate_partition_map_key():
       """
       新しいパーティションマップキーを生成

       Returns:
           生成されたパーティションマップキー
       """
       # 暗号論的に安全な乱数で生成
       random_bytes = os.urandom(16)
       # Base62エンコード（英数字のみ）
       key = base62.encodebytes(random_bytes)
       return key
   ```

4. 固定長シリアライズによる統計的区別不可能性確保

### ステップ 3: 完全固定長シリアライズの実装

1. `fixed_length_serialize()` 関数の機能拡張

   ```python
   def serialize_share_value(value, fixed_length=FIXED_VALUE_LENGTH):
       """
       シェア値を固定長でシリアライズする

       Args:
           value: シリアライズするシェア値
           fixed_length: 固定長（バイト数）

       Returns:
           固定長シリアライズされたシェア値
       """
       # シェア値を16進数文字列に変換
       hex_value = format(value, 'x')

       # 固定長に調整（短い場合はゼロパディング、長い場合は切り詰め）
       if len(hex_value) < fixed_length * 2:
           # 左側にゼロパディング
           padded_value = hex_value.zfill(fixed_length * 2)
       else:
           # 固定長に切り詰め
           padded_value = hex_value[-(fixed_length * 2):]

       return padded_value
   ```

2. 入力データサイズに関わらず同一の出力ファイルサイズを確保
3. 暗号化データと初期化データが統計的に区別できないよう実装
4. 全シェア値を固定長に変換（`FIXED_VALUE_LENGTH`で定義された長さに調整）
5. シリアライズ前後で情報の整合性を確保

### ステップ 4: 多段 MAP 方式の完全実装

1. 「第 1 段階 MAP」の実装

   ```python
   def generate_partition_map(partition_key, salt):
       """
       パーティションマップキーから第1段階MAPを生成

       Args:
           partition_key: パーティションマップキー
           salt: ソルト値

       Returns:
           第1段階MAP（シェアID候補のセット）
       """
       # パーティションキーとソルトからシード値を生成
       seed = hashlib.pbkdf2_hmac(
           'sha256',
           partition_key.encode(),
           salt,
           iterations=PBKDF2_ITERATIONS,
           dklen=32
       )

       # シードから決定論的に乱数ストリームを生成
       random.seed(int.from_bytes(seed, byteorder='big'))

       # パーティションマップを生成
       partition_map = set()
       while len(partition_map) < PARTITION_SIZE:
           # 1からSHARE_ID_SPACEまでの範囲でユニークなIDを生成
           share_id = random.randint(1, SHARE_ID_SPACE)
           partition_map.add(share_id)

       return partition_map
   ```

2. 「第 2 段階 MAP」の実装

   ```python
   def generate_password_map(password, salt, partition_map):
       """
       パスワードから第2段階MAPを生成

       Args:
           password: パスワード
           salt: ソルト値
           partition_map: 第1段階MAPで特定されたシェアIDセット

       Returns:
           第2段階MAP（実際に使用するシェアIDのセット）
       """
       # パスワードをUnicode正規化してハッシュ化
       normalized_password = unicodedata.normalize('NFKC', password)

       # アルゴン2を使用した鍵導出
       key = argon2.hash_password_raw(
           password=normalized_password.encode(),
           salt=salt,
           time_cost=ARGON2_TIME_COST,
           memory_cost=ARGON2_MEMORY_COST,
           parallelism=ARGON2_PARALLELISM,
           hash_len=ARGON2_OUTPUT_LENGTH
       )

       # シェアIDとスコアのマッピングを生成
       share_scores = {}
       for share_id in partition_map:
           # 各シェアIDに対してHMACを計算
           hmac_value = hmac.new(
               key,
               str(share_id).encode(),
               hashlib.sha256
           ).digest()

           # HMACから整数値（スコア）を生成
           score = int.from_bytes(hmac_value, byteorder='big')
           share_scores[share_id] = score

       # スコアで降順ソートし、上位ACTIVE_SHARES個を選択
       selected_shares = sorted(share_scores.keys(),
                               key=lambda x: share_scores[x],
                               reverse=True)[:ACTIVE_SHARES]

       return set(selected_shares)
   ```

3. `is_share_in_file_partition()` 関数の実装

   ```python
   def is_share_in_file_partition(share_id, partition_key, salt):
       """
       シェアIDが指定されたパーティションに属するか検証

       Args:
           share_id: 検証するシェアID
           partition_key: パーティションマップキー
           salt: ソルト値

       Returns:
           True: シェアがパーティションに属する
           False: シェアがパーティションに属さない
       """
       # パーティションマップを生成
       partition_map = generate_partition_map(partition_key, salt)

       # シェアIDがパーティション内にあるか確認
       return share_id in partition_map
   ```

4. コマンドラインインターフェースの実装

   **【重要: 実装しないオプションとアプローチ】**

   セキュリティ要件と直交処理原則に基づき、以下のオプションやアプローチは**絶対に実装しません**：

   - `--type` オプション: ファイル種別(A/B)を明示的に指定するオプション（セキュリティリスク）
   - パーティションマップキーの保存オプション: キーを保存する機能（情報漏洩リスク）
   - テスト暗号化モード: 暗号化をシミュレートするだけのモード（セキュリティ懸念）
   - 過去形式のファイル判定: 任意のファイル形式判定機能（評価が必要となるリスク）
   - エラーハンドリングとメッセージ表示: ファイル形式に関するエラー表示（判別処理が必要）
   - 形式互換性チェック: 新旧形式の互換性確認（判定と評価が必要）

   これらのオプションやアプローチは区別不能性の原則と直交処理原則に違反し、
   相補文書推測攻撃の可能性を生じさせるため、設計書の安全性要件に基づき明示的に禁止します。
   システムは一切の「判定」「評価」「条件分岐」「区別」処理を行わない設計とします。

### ステップ 5: 過去形式コードの削除確認

1. コードベース全体を検索し、過去形式関連の関数を特定

   ```bash
   # 過去形式関連コードを検索
   grep -r "v1_format\|v2_format\|convert_v1\|convert_v2" --include="*.py" .
   ```

2. 該当する関数とそれに関連するすべてのコードを削除
3. インポート文やコメントを含め、過去形式への参照をすべて削除
4. 単体テストから過去形式のテストも削除
5. `code_review_remove_old_formats()` を実行して削除完了を確認

### ステップ 6: 進捗表示機能の実装

処理の進行状況をユーザーに視覚的に伝える進捗表示機能を実装します：

```python
def process_with_progress(total_items, operation_name="処理"):
    """
    進捗表示機能付きの処理ラッパー

    Args:
        total_items: 処理する総アイテム数
        operation_name: 操作の名前（表示用）

    Returns:
        進捗表示用のジェネレータ関数
    """
    start_time = time.time()

    def progress_tracker(current_item):
        """進捗を表示するジェネレータ関数"""
        progress = (current_item + 1) / total_items * 100
        elapsed = time.time() - start_time

        # 残り時間の推定（最低1処理完了後）
        if current_item > 0:
            eta = elapsed / (current_item + 1) * (total_items - current_item - 1)
            eta_str = f"残り時間: {eta:.1f}秒"
        else:
            eta_str = "残り時間: 計算中..."

        # プログレスバー（幅30文字）
        bar_width = 30
        bar_filled = int(bar_width * progress / 100)
        bar = '█' * bar_filled + '░' * (bar_width - bar_filled)

        # 進捗情報をコンソールに表示（同じ行を更新）
        sys.stdout.write(f"\r{operation_name}: {progress:.1f}% |{bar}| {current_item+1}/{total_items} {eta_str}")
        sys.stdout.flush()

        # 最後のアイテムの場合は改行
        if current_item == total_items - 1:
            total_time = time.time() - start_time
            sys.stdout.write(f"\n{operation_name}が完了しました。合計時間: {total_time:.1f}秒\n")
            sys.stdout.flush()

    return progress_tracker
```

この進捗表示機能を以下の処理に適用します：

1. **暗号化処理**:

   ```python
   def encrypt_data_with_progress(data, partition_key, password, output_path):
       """
       進捗表示機能付きの暗号化処理

       Args:
           data: 暗号化するデータ
           partition_key: パーティションマップキー
           password: パスワード
           output_path: 出力ファイルパス
       """
       # データをチャンクに分割
       chunks = split_into_chunks(data, CHUNK_SIZE)
       total_chunks = len(chunks)

       # 進捗表示機能を初期化
       progress = process_with_progress(total_chunks, "暗号化")

       # 各チャンクを処理
       encrypted_chunks = []
       for i, chunk in enumerate(chunks):
           # シェア生成処理
           shares = generate_shares_from_chunk(chunk, partition_key, password)
           encrypted_chunks.append(shares)

           # 進捗更新
           progress(i)

       # 暗号化ファイルに書き込み
       write_encrypted_file(encrypted_chunks, output_path)
   ```

2. **復号処理**:

   ```python
   def decrypt_data_with_progress(encrypted_file, partition_key, password):
       """
       進捗表示機能付きの復号処理

       Args:
           encrypted_file: 暗号化ファイルパス
           partition_key: パーティションマップキー
           password: パスワード

       Returns:
           復号されたデータ
       """
       # 暗号化ファイルからチャンクを読み込み
       encrypted_chunks = read_encrypted_file(encrypted_file)
       total_chunks = len(encrypted_chunks)

       # 進捗表示機能を初期化
       progress = process_with_progress(total_chunks, "復号")

       # 各チャンクを処理
       decrypted_chunks = []
       for i, chunk in enumerate(encrypted_chunks):
           # シェアから秘密を復元
           decrypted_chunk = reconstruct_secret_from_shares(chunk, partition_key, password)
           decrypted_chunks.append(decrypted_chunk)

           # 進捗更新
           progress(i)

       # 復号したチャンクを結合
       return combine_chunks(decrypted_chunks)
   ```

3. **初期化処理**:

   ```python
   def initialize_with_progress(output_path=None):
       """
       進捗表示機能付きの初期化処理

       Args:
           output_path: 出力ファイルパス（省略可）

       Returns:
           生成したファイルパス
       """
       # 全シェアID数
       total_shares = SHARE_ID_SPACE

       # 進捗表示機能を初期化
       progress = process_with_progress(total_shares, "初期化")

       # 全シェアをガベージシェアで埋める
       shares = {}
       for i in range(1, total_shares + 1):
           shares[i] = generate_garbage_share_value()

           # 進捗更新（100シェアごと）
           if i % 100 == 0 or i == total_shares:
               progress(i - 1)

       # 暗号化ファイルに書き込み
       return generate_empty_encrypted_file_with_shares(shares, output_path)
   ```

この進捗表示機能により、長時間の暗号化・復号処理中にユーザーが処理状況を視覚的に把握できるようになり、ユーザーエクスペリエンスが大幅に向上します。大量のシェアを処理する場合でも、ユーザーは残り時間を確認しながら操作を続けることができます。

## 情報漏洩リスクの低減対策

実装全体を通して、以下の情報漏洩リスク低減対策を徹底します：

1. **ファイル内メタデータの極小化**: ソルト値のみを含むヘッダー構造
2. **ファイル名からの情報漏洩防止**: 時間情報を含まない UUID 命名方式
3. **パーティションマップキーの非保存**: システム側でパーティションマップキーを一切保存しない
4. **多段 MAP 方式の徹底**: 全てのシェア位置をパーティションマップキーとパスワードから決定論的に導出
5. **ファイル種別の隠蔽**: ファイル名からファイル種別を識別できないようにする
6. **統計的区別不可能性の確保**: 初期化ファイルと暗号化済みファイルが外部から区別できないようにする
7. **過去形式コードの完全排除**: コードベース内に過去形式関連コードを一切残さない
8. **完全固定長シリアライズ**: データ量に関わらず同一のシリアライズ処理を適用
9. **判定・評価の排除**: 形式判定やエラーハンドリングを実装せず、直交処理原則を徹底

## 実装順序と優先度

以下の優先順位で実装を進めます：

1. **最優先：パーティション設計パラメータの定義** - `constants.py`の更新
2. **優先度高：ガベージシェア生成と初期化機能** - セキュリティの基盤となる部分
3. **優先度高：多段 MAP 方式の実装** - システムの核心機能
4. **優先度中：完全固定長シリアライズ** - 効率化と統計的区別不可能性の確保
5. **優先度中：進捗表示機能の実装** - 長時間処理のユーザー体験向上
6. **優先度低：過去形式コードの削除** - セキュリティ向上のための最終ステップ

各実装は単体テストと統合テストを同時に開発し、設計書の理念と原則への完全準拠を確認します。

## テスト計画

1. **ユニットテスト**:

   - パーティション設計パラメータのテスト
   - 多段 MAP 方式の検証（第 1 段階・第 2 段階 MAP）
   - 完全固定長シリアライズのテスト
   - ファイル生成と読み取り機能テスト
   - 進捗表示機能のテスト

2. **統合テスト**:

   - 初期化 → 暗号化 → 更新 → 復号の全サイクルテスト
   - 設計書の理念（多段 MAP 方式、全シェア使用方式、統計的区別不可能性）の検証
   - ファイル混在保管機能テスト
   - パーティションマップキー・パスワード組み合わせの検証
   - 進捗表示付き処理の完全テスト

3. **セキュリティテスト**:

   - 統計的区別不可能性の証明（初期化/暗号化ファイル、ファイル A/B 間）
   - ファイルサイズ一貫性の検証
   - サイドチャネル耐性テスト（直交処理原則と直線的処理の検証）
   - メタデータ極小化による情報漏洩防止効果の検証
   - ファイル名からの情報漏洩リスク検証
   - ブルートフォース攻撃耐性テスト
   - 判定・評価処理の不在確認
   - 過去形式コード削除の完全性検証

## 成功基準

1. シェアフォーマットのサイズ効率: 新しい形式によるサイズ削減率 40%以上
2. 設計書のセキュリティ基準への準拠度: 100%
3. 設計書の理念・原則への準拠度: 100%
4. ユニットテスト成功率: 100%
5. 統計的区別不可能性: 初期化/暗号化ファイル間、ファイル A/B 間の区別が統計的に不可能
6. 最小限ヘッダー情報での正常動作: ソルト値のみで完全動作
7. ファイル名からの情報漏洩リスク: 0%
8. ファイル混在保管の完全実装: ファイル A/B が同一暗号ファイル内に正しく混在保管
9. 過去形式の完全排除: 変換機能なしで 100%排除
10. 過去形式コードの完全削除: コードベースから 100%削除
11. 進捗表示機能の有効性: 大規模ファイル処理時でもユーザー体験を確保
12. 判定・評価処理の不存在: 形式判定・エラーハンドリングが一切存在しないこと

以上の実装により、システムのセキュリティと効率性が大幅に向上し、設計書の理念と原則に完全準拠したシステムが実現します。パーティション設計パラメータの明示的定義と多段 MAP 方式の完全実装により、セキュリティが強化されます。完全固定長シリアライズと統計的区別不可能性の実現により、暗号解析への耐性が向上します。メタデータの極小化とガベージシェアの適切な実装により、情報漏洩リスクが低減します。また、進捗表示機能の追加により、長時間処理における操作性とユーザーエクスペリエンスが向上します。さらに、判定・評価処理の排除により、直交処理原則を徹底し、システムの区別不能性を高めます。

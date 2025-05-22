# シャミア秘密分散法による複数平文復号システム設計書

## 8. 利用ガイドライン

### 8.1. パスワード管理ガイドライン

#### 8.1.1. パスワード強度推奨事項

セキュリティを確保するため、以下のパスワード強度を推奨します：

1. **最小長**: 12 文字以上
2. **複雑性**: 大文字、小文字、数字、特殊文字を含む
3. **エントロピー**: 最低 60 ビット以上のエントロピーを持つ
4. **言語**: UTF-8 でサポートされるすべての文字（漢字、絵文字なども含む）が使用可能
5. **パスワード使用**: パーティションマップキーの暗号化には**全文そのままのパスワード（生のパスワード）**が使用され、第 2 段階 MAP 生成には**必ず処理（ハッシュ化）されたパスワード**が使用される（**開発者は第 2 段階 MAP 生成に生のパスワードを誤って使用してはならない**）

#### 8.1.2. パスワード保管に関する注意

1. **分離保管**: パスワードとパーティションマップキーは別々の場所に保管
2. **バックアップ**: パスワードとパーティションマップキーの安全なバックアップを作成
3. **共有方法**: 必要に応じて分散保管方式（他の暗号技術と組み合わせ）の使用を検討
4. **更新頻度**: 定期的なパスワード更新より、強力な初期パスワードの使用を推奨

### 8.2. 暗号書庫管理ガイドライン

#### 8.2.1. 適切なファイルパーティション設計

目的に応じた適切なパラメータ設定を以下に示します：

| 用途             | ACTIVE_SHARES | PARTITION_SIZE | 特徴                                           |
| ---------------- | ------------- | -------------- | ---------------------------------------------- |
| 標準的な保護     | 8             | 24             | バランスの取れたセキュリティと性能             |
| 高セキュリティ   | 16            | 48             | 最大限のセキュリティ（性能は若干低下）         |
| リソース制約環境 | 4             | 16             | 最小限のリソース要件（セキュリティは若干低下） |
| 大容量データ     | 8             | 32             | 大きな JSON データの保存に最適                 |

#### 8.2.2. バックアップと復旧戦略

1. **定期バックアップ**:

   - 暗号書庫ファイルの定期的なバックアップ
   - ファイル破損に備えた複数世代のバックアップ保持

2. **障害復旧**:

   - システムが WAL 方式による自動復旧を試みるが、重大な破損時には手動復旧が必要
   - バックアップからの復元手順を事前に準備

3. **バックアップローテーション**:
   - `BACKUP_RETENTION_DAYS`設定による古いバックアップの自動削除
   - 重要なデータの場合は長期アーカイブの検討

### 8.3. アプリケーション統合ガイドライン

#### 8.3.1. 基本的な使用パターン

1. **初期化と設定**:

   ```python
   # 暗号書庫の作成
   createCryptoStorage(
       file_path="secure_storage.dat",
       partition_map_key_a=encrypt_partition_map(partition_distribution_a, password_a),
       partition_map_key_b=encrypt_partition_map(partition_distribution_b, password_b),
       password_a=password_a,  # 全文そのままのパスワード
       password_b=password_b   # 全文そのままのパスワード
   )
   ```

2. **データ保存**:

   ```python
   # A用のデータを保存
   updateCryptoStorage(
       file_path="secure_storage.dat",
       json_data=json.dumps({"key": "value_for_A"}),
       partition_map_key=a_partition_map_key,  # パーティションマップキーA
       password=password_a  # パスワードA（全文そのまま）
   )

   # B用のデータを保存
   updateCryptoStorage(
       file_path="secure_storage.dat",
       json_data=json.dumps({"key": "value_for_B"}),
       partition_map_key=b_partition_map_key,  # パーティションマップキーB
       password=password_b  # パスワードB（全文そのまま）
   )
   ```

3. **データ読み取り**:

   ```python
   # A用のデータを読み取り
   json_data_a = readCryptoStorage(
       file_path="secure_storage.dat",
       partition_map_key=a_partition_map_key,  # パーティションマップキーA
       password=password_a  # パスワードA（全文そのまま）
   )

   # B用のデータを読み取り
   json_data_b = readCryptoStorage(
       file_path="secure_storage.dat",
       partition_map_key=b_partition_map_key,  # パーティションマップキーB
       password=password_b  # パスワードB（全文そのまま）
   )
   ```

#### 8.3.2. エラー処理パターン

1. **正常な失敗シナリオ**:

   ```python
   try:
       # 暗号書庫からデータを読み取り
       data = readCryptoStorage(file_path, partition_map_key, password)

       # 返されたデータが有効なJSONかどうかを確認
       is_valid, parsed = validate_json(data)
       if not is_valid:
           print("無効なパスワードまたはパーティションマップキーが使用された可能性があります")
       else:
           # 有効なデータを処理
           process_data(parsed)
   except Exception as e:
       print(f"エラーが発生しました: {e}")
   ```

2. **WAL 復旧処理**:
   ```python
   def safe_update(file_path, json_data, partition_map_key, password):
       try:
           result = updateCryptoStorage(file_path, json_data, partition_map_key, password)
           return result
       except Exception as e:
           # ロックファイルを確認
           lock_path = file_path + ".lock"
           if os.path.exists(lock_path):
               # 自動復旧を試みる
               recover_from_backup(file_path)
               # ロックを解放
               os.remove(lock_path)
           raise e
   ```

#### 8.3.3. パフォーマンス最適化パターン

1. **キャッシング**:

   ```python
   # パスワード処理結果のキャッシング
   processed_password_cache = {}

   def get_processed_password(password):
       if password not in processed_password_cache:
           processed_password_cache[password] = process_password(password)
       return processed_password_cache[password]
   ```

2. **並列処理**:

   ```python
   import concurrent.futures

   def process_chunks_parallel(chunks, func, max_workers=None):
       with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
           results = list(executor.map(func, chunks))
       return results
   ```

### 8.4. セキュリティプラクティス

#### 8.4.1. 安全な展開と運用

1. **配置の安全性**:

   - セキュアな環境への暗号書庫配置
   - アクセス制御の適切な設定
   - 読み取り専用メディアの使用検討

2. **鍵管理**:

   - パーティションマップキーは**全文そのままのパスワード（生のパスワード）**で暗号化
   - 第 2 段階 MAP の生成には**必ず処理されたパスワード**を使用（**開発者は生のパスワードを誤って使用してはならない**）
   - パスワードとパーティションマップキーの安全な管理と分離

3. **監査と監視**:
   - アクセス試行のログ記録（オプション）
   - 異常アクセスパターンの検出

#### 8.4.2. 安全な更新と破棄

1. **更新プロセス**:

   - WAL 方式による安全な更新
   - 更新中の障害に対する自動復旧

2. **安全な破棄**:

   - 不要になった暗号書庫の安全な削除
   - メモリ内の機密データの明示的な消去

3. **鍵ローテーション**:
   - 定期的なパーティションマップキーのローテーション
   - 新旧のパーティションマップキーの安全な管理

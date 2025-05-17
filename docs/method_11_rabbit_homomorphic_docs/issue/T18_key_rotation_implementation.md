# 📝 鍵ローテーション実装指示書（T18） - ラビット＋準同型マスキング暗号プロセッサ 🔐

> **ドキュメント種別: 実装指示書**

## 🌟 タスク進捗状況

タスク実装フェーズの進捗:

- 🔄 **フェーズ 0**: 実装準備 [**現在作業中**]
- ⏳ **フェーズ 1**: 基盤ユーティリティ実装 [予定]
- ⏳ **フェーズ 2**: セキュリティ対策基盤実装 [予定]
- ⏳ **フェーズ 3**: 三暗号方式コア実装 [予定]
- ⏳ **フェーズ 4**: 融合機能と変換システム実装 [予定]
- ⏳ **フェーズ 5**: データ形式とインターフェース実装 [予定]
- ⏳ **フェーズ 6**: 検証とパフォーマンス最適化 [予定]

### 📋 現在の実装フェーズ: `フェーズ0: 実装準備`

**現在のタスク**: T18（鍵ローテーション実装）
**進捗状況**: T1-T17 完了 → **T18 実装中** → T19-T115 未着手

**注**: 各タスクは独立して実装・完了させてください。

### 🎯 タスク範囲（T18: 鍵ローテーション実装）

**実装すべきもの**:

- ✅ `utils/key/key_rotation.py`
- ✅ 関連するテスト

**実装してはいけないもの**:

- ❌ `utils/secure_key_derivation/quantum_salt.py`（次のタスク T19）
- ❌ `utils/secure_key_derivation/qkdf.py`（タスク T20）
- ❌ 他の機能（T19 以降のタスク）

**実装がベストプラクティスに反する可能性がある場合**: 作業を即時停止し、問題を報告してください。

## 📝 課題の詳細

### 🎯 タスク概要

本タスク（T18）では鍵ローテーション機能を実装します。T15 で実装した鍵管理基本機能、T16 で実装した鍵保存・読込機能、および T17 で実装した鍵検証・強度評価機能と連携し、暗号鍵の定期的な更新を安全かつ効率的に実施するための機能を提供します。このコンポーネントは鍵のライフサイクル管理において重要な役割を果たし、長期的なシステムセキュリティを確保します。

**本タスク（T18）の作業カウント**:

- 📝 **実装作業**: 10 件

  - 鍵ローテーションスケジュール管理機能: 3 関数
  - 鍵更新実行機能: 2 関数
  - 安全な鍵移行機能: 3 関数
  - 鍵バージョン管理機能: 2 関数

- 🧪 **テスト作業**: 4 件

  - 鍵ローテーションスケジュール管理機能テスト
  - 鍵更新実行機能テスト
  - 安全な鍵移行機能テスト
  - 鍵バージョン管理機能テスト

- ✅ **完了条件**: 25 項目
  - 実装完了条件: 5 項目
  - 機能完了条件: 5 項目
  - テスト完了条件: 5 項目
  - ドキュメント完了条件: 5 項目
  - 納品物件検証条件: 5 項目

### 🔍 背景と目的

ラビット＋準同型マスキング暗号プロセッサにおいて、暗号鍵は時間の経過とともに暗号解読リスクが高まります。定期的な鍵ローテーションは、潜在的な暗号解析攻撃の影響を軽減し、長期的なシステムセキュリティを確保するための必須プラクティスです。本タスクでは、鍵の定期的な更新を自動化するだけでなく、古い鍵から新しい鍵への安全な移行プロセスを含む、包括的な鍵ローテーション機能を実装します。

特に、第二回暗号解読キャンペーンで発見された脆弱性を考慮し、ローテーション時の鍵情報の漏洩や移行プロセスにおける一時的な脆弱性を防止する機能を提供します。また、Tri-Fusion アーキテクチャの三暗号方式における整合性を維持しながら鍵を更新する機能も含まれ、鍵のローテーションによって暗号化されたデータの復号能力が損なわれないことを保証します。

### 📊 要件仕様

1. T15（鍵管理基本機能）、T16（鍵保存・読込機能）、T17（鍵検証・強度評価機能）と連携して動作すること
2. 鍵の使用頻度、経過時間、強度評価などに基づく柔軟なローテーションスケジュールを定義できること
3. 自動的かつ透過的に鍵のローテーションを実行できること
4. 鍵ローテーション中もシステムの稼働を継続できるよう、無停止移行をサポートすること
5. 古い鍵から新しい鍵への漸進的な移行プロセスを管理できること
6. ローテーション実行中の攻撃に対して耐性を持つこと（アトミックな更新操作）
7. 鍵のバージョン管理と履歴追跡を提供すること
8. ローテーション操作の監査ログを生成すること（T1: ロギング基盤との連携）
9. 緊急時の強制ローテーション機能を提供すること
10. 三暗号方式（ラビットストリーム、準同型暗号、量子耐性レイヤー）間の鍵の整合性を維持すること

### 🛠️ 実装内容詳細

#### 1. 鍵ローテーションスケジュール管理機能（3 つの関数）

```python
def create_rotation_schedule(key_id: str, schedule_params: dict) -> dict:
    """
    鍵の自動ローテーションスケジュールを作成する

    Args:
        key_id: ローテーションスケジュールを設定する鍵のID
        schedule_params: スケジュールパラメータを含む辞書
          必須パラメータ:
          - "rotation_type": ローテーションタイプ
            - "time_based" - 経過時間に基づくローテーション
            - "usage_based" - 使用回数に基づくローテーション
            - "hybrid" - 時間と使用回数の両方に基づくローテーション
            - "threshold_based" - 強度評価に基づくローテーション

          タイプ固有のパラメータ:
          - "time_based"の場合:
            - "interval_days": int - ローテーション間隔（日数）
            - "max_age_days": int - 鍵の最大有効期間（日数）
          - "usage_based"の場合:
            - "max_operations": int - 最大使用回数
            - "warning_threshold": int - 警告表示の使用回数閾値
          - "hybrid"の場合:
            - time_basedとusage_basedの両方のパラメータ
          - "threshold_based"の場合:
            - "min_strength_score": float - 最小強度スコア閾値（0.0～10.0）
            - "verification_interval_days": int - 強度検証の間隔（日数）

    Returns:
        作成されたローテーションスケジュール情報を含む辞書
        {
          "schedule_id": str,  # スケジュールの一意識別子
          "key_id": str,  # 関連する鍵ID
          "rotation_type": str,  # ローテーションタイプ
          "parameters": dict,  # 設定されたパラメータ
          "next_rotation": {  # 次回ローテーション予定
            "estimated_date": str,  # 推定日時（ISO 8601形式）
            "reason": str,  # ローテーション理由
          },
          "created_at": str,  # 作成日時（ISO 8601形式）
          "updated_at": str,  # 最終更新日時（ISO 8601形式）
        }

    Raises:
        ValueError: key_idが存在しない場合
        ValueError: schedule_paramsに必須パラメータが不足している場合
        ValueError: schedule_paramsに無効なパラメータ値が含まれている場合
        KeyManagementError: スケジュール作成に失敗した場合

    実装詳細:
    1. 引数の検証:
       - key_idの存在確認（key_manager.get_key_info()を使用）
       - schedule_paramsの必須パラメータ確認
       - パラメータ値の範囲と型の検証
    2. スケジュールIDの生成（UUID v4）
    3. ローテーションタイプに基づく次回ローテーション日時の計算:
       - "time_based": 現在時刻 + interval_days
       - "usage_based": 使用回数に基づく推定日時
       - "hybrid": 時間と使用回数の推定の早い方
       - "threshold_based": 現在時刻 + verification_interval_days
    4. スケジュール情報の構築
    5. スケジュール情報の保存（key_storageと連携）
    6. ログ出力（スケジュール作成イベント、key_idとスケジュールIDのみ）
    7. スケジュール情報の返却
    """
    pass

def get_rotation_schedule(schedule_id: str = None, key_id: str = None) -> Union[dict, list]:
    """
    鍵ローテーションスケジュールの情報を取得する

    Args:
        schedule_id: 取得するスケジュールの識別子（省略可）
        key_id: 鍵IDに関連するすべてのスケジュールを取得（省略可）

        注: schedule_idとkey_idの少なくとも一方を指定する必要がある
        両方指定された場合はschedule_idが優先される

    Returns:
        schedule_idが指定された場合: 単一のスケジュール情報辞書
        key_idのみが指定された場合: スケジュール情報辞書のリスト

        スケジュール情報辞書の形式:
        {
          "schedule_id": str,  # スケジュールの一意識別子
          "key_id": str,  # 関連する鍵ID
          "rotation_type": str,  # ローテーションタイプ
          "parameters": dict,  # 設定されたパラメータ
          "next_rotation": {  # 次回ローテーション予定
            "estimated_date": str,  # 推定日時（ISO 8601形式）
            "reason": str,  # ローテーション理由
          },
          "status": str,  # スケジュール状態 ("active", "suspended", "completed")
          "created_at": str,  # 作成日時
          "updated_at": str,  # 最終更新日時
          "last_rotation": {  # 最終ローテーション情報（実行済みの場合）
            "date": str,  # 実行日時
            "from_key_version": str,  # 元の鍵バージョン
            "to_key_version": str,  # 新しい鍵バージョン
            "status": str,  # ステータス ("success", "failed", "partial")
          }
        }

    Raises:
        ValueError: schedule_idとkey_idの両方がNoneの場合
        ValueError: 指定されたschedule_idまたはkey_idが存在しない場合
        KeyManagementError: スケジュール情報の取得に失敗した場合

    実装詳細:
    1. 引数の検証:
       - schedule_idかkey_idの少なくとも一方が指定されているか確認
       - schedule_idが指定されている場合はその存在を確認
       - key_idが指定されている場合はその存在を確認（key_manager.get_key_info()を使用）
    2. スケジュール情報の取得（key_storageと連携）
    3. 各スケジュールの次回ローテーション日時を再計算して最新化
    4. ログ出力（スケジュール情報取得イベント、schedule_idまたはkey_idのみ）
    5. スケジュール情報の返却
    """
    pass

def update_rotation_schedule(schedule_id: str, updated_params: dict) -> dict:
    """
    既存の鍵ローテーションスケジュールを更新する

    Args:
        schedule_id: 更新するスケジュールの識別子
        updated_params: 更新するパラメータを含む辞書
          更新可能なパラメータ:
          - "rotation_type": ローテーションタイプの変更
          - "parameters": スケジュールパラメータの更新
          - "status": スケジュール状態の変更 ("active", "suspended")

    Returns:
        更新されたスケジュール情報を含む辞書（get_rotation_scheduleと同じ形式）

    Raises:
        ValueError: schedule_idが存在しない場合
        ValueError: updated_paramsに無効なパラメータが含まれている場合
        ValueError: 更新操作が論理的に矛盾する場合（例: 完了済みスケジュールの再アクティブ化）
        KeyManagementError: スケジュール更新に失敗した場合

    実装詳細:
    1. 引数の検証:
       - schedule_idの存在確認
       - updated_paramsの内容検証
    2. 現在のスケジュール情報の取得（get_rotation_scheduleを使用）
    3. 更新内容の妥当性確認:
       - 完了済みスケジュールの更新不可
       - パラメータ値の範囲と型の検証
    4. スケジュール情報の更新
    5. ローテーションタイプまたはパラメータが変更された場合、次回ローテーション日時を再計算
    6. 更新されたスケジュール情報の保存（key_storageと連携）
    7. ログ出力（スケジュール更新イベント、schedule_idのみ）
    8. 更新されたスケジュール情報の返却
    """
    pass
```

#### 2. 鍵更新実行機能（2 つの関数）

```python
def execute_rotation(schedule_id: str = None, key_id: str = None, force: bool = False) -> dict:
    """
    鍵ローテーションを実行する

    Args:
        schedule_id: 実行するローテーションスケジュールの識別子（省略可）
        key_id: ローテーションする鍵のID（省略可）
        force: 強制ローテーションを実行するかどうか（デフォルト: False）
               Trueの場合、スケジュール条件に関わらず即時ローテーションを実行

        注: schedule_idとkey_idの少なくとも一方を指定する必要がある
        両方指定された場合はschedule_idが優先される

    Returns:
        ローテーション実行結果を含む辞書
        {
          "rotation_id": str,  # ローテーション操作の一意識別子
          "key_id": str,  # ローテーションされた鍵ID
          "schedule_id": str,  # 関連するスケジュールID（スケジュールに基づく場合）
          "status": str,  # ステータス ("success", "failed", "partial")
          "started_at": str,  # 開始日時（ISO 8601形式）
          "completed_at": str,  # 完了日時（ISO 8601形式）
          "from_key_version": str,  # 元の鍵バージョン
          "to_key_version": str,  # 新しい鍵バージョン
          "details": {  # 詳細情報
            "force_executed": bool,  # 強制実行されたかどうか
            "rotation_reason": str,  # ローテーション理由
            "migration_status": str,  # 移行ステータス
            "backup_created": bool,  # バックアップが作成されたか
          },
          "error": str,  # エラー詳細（失敗した場合）
        }

    Raises:
        ValueError: schedule_idとkey_idの両方がNoneの場合
        ValueError: 指定されたschedule_idが存在しない場合
        ValueError: 指定されたkey_idが存在しない場合
        KeyManagementError: ローテーション実行に失敗した場合

    実装詳細:
    1. 引数の検証:
       - schedule_idかkey_idの少なくとも一方が指定されているか確認
       - schedule_idが指定されている場合はその存在を確認
       - key_idが指定されている場合はその存在を確認（key_manager.get_key_info()を使用）
    2. ローテーション操作IDの生成（UUID v4）
    3. ローテーション前の検証:
       - 鍵の現在の強度評価（verify_key_qualityを使用）
       - ローテーション条件の確認（forceがFalseの場合）
    4. ロギング開始（ローテーション開始イベント）
    5. 新しい鍵の生成:
       - key_manager.generate_key()を使用
       - 新しい鍵の品質検証（verify_key_qualityを使用）
    6. 鍵の安全な移行:
       - migrate_to_new_key()を使用
    7. 新旧鍵のバージョン関係の記録:
       - track_key_version()を使用
    8. スケジュール情報の更新（schedule_idが指定されている場合）:
       - 最終ローテーション情報の更新
       - 次回ローテーション日時の再計算
    9. ロギング完了（ローテーション完了イベント）
    10. ローテーション結果の返却
    """
    pass

def check_pending_rotations() -> list:
    """
    期限を迎えた、または近づいているローテーションスケジュールを確認する

    Args:
        なし

    Returns:
        保留中のローテーション情報のリスト
        [
          {
            "schedule_id": str,  # スケジュールの一意識別子
            "key_id": str,  # 関連する鍵ID
            "key_alias": str,  # 鍵エイリアス（設定されている場合）
            "status": str,  # ステータス ("due", "upcoming", "overdue")
            "due_date": str,  # 予定日時（ISO 8601形式）
            "days_remaining": int,  # 残り日数（負の値は期限超過を示す）
            "rotation_type": str,  # ローテーションタイプ
            "priority": str,  # 優先度 ("high", "medium", "low")
          },
          ... 他の保留中ローテーション ...
        ]

    Raises:
        KeyManagementError: ローテーションスケジュール情報の取得に失敗した場合

    実装詳細:
    1. すべてのアクティブなローテーションスケジュールの取得
    2. 各スケジュールに対して:
       - 次回ローテーション日時の確認
       - 現在時刻との比較
       - ステータスの判定:
         - "overdue": 期限超過
         - "due": 当日または翌日が期限
         - "upcoming": 7日以内が期限
       - 優先度の判定:
         - "high": 期限超過または当日が期限
         - "medium": 3日以内が期限
         - "low": 7日以内が期限
    3. 結果のソート（優先度の高い順）
    4. ログ出力（保留中ローテーション確認イベント、該当件数のみ）
    5. 保留中ローテーションリストの返却
    """
    pass
```

#### 3. 安全な鍵移行機能（3 つの関数）

```python
def migrate_to_new_key(old_key_id: str, new_key_id: str, migration_params: dict = None) -> dict:
    """
    古い鍵から新しい鍵への安全な移行を実行する

    Args:
        old_key_id: 現在使用中の鍵のID
        new_key_id: 移行先の新しい鍵のID
        migration_params: 移行パラメータを含む辞書（省略可）
          設定可能なパラメータ:
          - "migration_strategy": 移行戦略
            - "immediate" - 即時切り替え
            - "gradual" - 漸進的移行
            - "dual_operation" - 二重運用期間あり
          - "dual_phase_duration_days": int - 二重運用期間（日数、"dual_operation"の場合）
          - "reencrypt_existing_data": bool - 既存データの再暗号化（デフォルト: False）
          - "backup_old_key": bool - 古い鍵のバックアップ作成（デフォルト: True）

    Returns:
        移行結果を含む辞書
        {
          "migration_id": str,  # 移行操作の一意識別子
          "status": str,  # ステータス ("success", "in_progress", "failed")
          "old_key_id": str,  # 元の鍵ID
          "new_key_id": str,  # 新しい鍵ID
          "started_at": str,  # 開始日時（ISO 8601形式）
          "completed_at": str,  # 完了日時（ISO 8601形式、完了時のみ）
          "strategy": str,  # 適用された移行戦略
          "phases": [  # 移行フェーズ情報
            {
              "phase": str,  # フェーズ名
              "status": str,  # フェーズ状態
              "started_at": str,  # フェーズ開始時間
              "completed_at": str,  # フェーズ完了時間（完了時のみ）
            },
            ... 他のフェーズ ...
          ],
          "backup_location": str,  # バックアップ保存場所（バックアップ作成時）
          "error": str,  # エラー詳細（失敗した場合）
        }

    Raises:
        ValueError: old_key_idまたはnew_key_idが存在しない場合
        ValueError: migration_paramsに無効なパラメータが含まれている場合
        KeyManagementError: 鍵移行に失敗した場合

    実装詳細:
    1. 引数の検証:
       - old_key_idとnew_key_idの存在確認
       - migration_paramsの内容検証
    2. デフォルトパラメータの設定（省略された場合）
    3. 移行操作IDの生成（UUID v4）
    4. ロギング開始（鍵移行開始イベント）
    5. 古い鍵のバックアップ（backup_old_keyがTrueの場合）:
       - key_storage.backup_key()を使用
    6. 移行戦略に基づく処理:
       - "immediate": 直ちに新しい鍵に切り替え
       - "gradual": 段階的に使用率を高める設定
       - "dual_operation": 両方の鍵を一定期間並行運用
    7. システムメタデータ更新（鍵参照を更新）
    8. 既存データの再暗号化（reencrypt_existing_dataがTrueの場合）:
       - 暗号化されたデータの特定と再暗号化
    9. 移行完了処理:
       - 古い鍵のアーカイブまたは非アクティブ化
       - 新しい鍵をデフォルトとして設定
    10. ロギング完了（鍵移行完了イベント）
    11. 移行結果の返却
    """
    pass

def abort_migration(migration_id: str) -> dict:
    """
    進行中の鍵移行を中止しロールバックする

    Args:
        migration_id: 中止する移行操作の識別子

    Returns:
        中止結果を含む辞書
        {
          "migration_id": str,  # 移行操作の一意識別子
          "status": str,  # ステータス ("aborted", "rollback_failed")
          "aborted_at": str,  # 中止日時（ISO 8601形式）
          "rollback_status": str,  # ロールバック状態
          "original_state": {  # 元の状態情報
            "old_key_id": str,  # 元の鍵ID
            "new_key_id": str,  # 新しい鍵ID
            "strategy": str,  # 適用されていた移行戦略
          },
          "reason": str,  # 中止理由（指定された場合）
          "error": str,  # エラー詳細（ロールバック失敗時）
        }

    Raises:
        ValueError: migration_idが存在しない場合
        ValueError: 指定された移行が既に完了または中止されている場合
        KeyManagementError: 移行中止またはロールバックに失敗した場合

    実装詳細:
    1. 引数の検証:
       - migration_idの存在確認
       - 移行状態の確認（"in_progress"であること）
    2. ロギング開始（移行中止イベント）
    3. 移行操作の中止:
       - 進行中のタスクの停止
    4. 元の状態へのロールバック:
       - 古い鍵をアクティブ状態に戻す
       - 新しい鍵を非アクティブ化
       - システムメタデータの復元
    5. 部分的に再暗号化されたデータの処理:
       - 古い鍵で再暗号化または復元
    6. 移行メタデータの更新:
       - ステータスを"aborted"に設定
       - 中止理由と時刻の記録
    7. ロギング完了（移行中止完了イベント）
    8. 中止結果の返却
    """
    pass

def get_migration_status(migration_id: str = None, key_id: str = None) -> Union[dict, list]:
    """
    鍵移行の状態を取得する

    Args:
        migration_id: 取得する移行操作の識別子（省略可）
        key_id: 鍵IDに関連するすべての移行を取得（省略可）

        注: migration_idとkey_idの少なくとも一方を指定する必要がある
        両方指定された場合はmigration_idが優先される

    Returns:
        migration_idが指定された場合: 単一の移行情報辞書
        key_idのみが指定された場合: 移行情報辞書のリスト（新旧両方の鍵IDに関連する移行を含む）

        移行情報辞書の形式:
        {
          "migration_id": str,  # 移行操作の一意識別子
          "status": str,  # ステータス ("success", "in_progress", "failed", "aborted")
          "old_key_id": str,  # 元の鍵ID
          "new_key_id": str,  # 新しい鍵ID
          "started_at": str,  # 開始日時
          "completed_at": str,  # 完了日時（完了時のみ）
          "strategy": str,  # 適用された移行戦略
          "progress": float,  # 進捗率（0.0～1.0、進行中の場合）
          "current_phase": str,  # 現在のフェーズ（進行中の場合）
          "phases": [  # 移行フェーズ情報
            {
              "phase": str,  # フェーズ名
              "status": str,  # フェーズ状態
              "started_at": str,  # フェーズ開始時間
              "completed_at": str,  # フェーズ完了時間（完了時のみ）
            },
            ... 他のフェーズ ...
          ],
          "error": str,  # エラー詳細（失敗した場合）
        }

    Raises:
        ValueError: migration_idとkey_idの両方がNoneの場合
        ValueError: 指定されたmigration_idまたはkey_idが存在しない場合
        KeyManagementError: 移行状態の取得に失敗した場合

    実装詳細:
    1. 引数の検証:
       - migration_idかkey_idの少なくとも一方が指定されているか確認
       - migration_idが指定されている場合はその存在を確認
       - key_idが指定されている場合はその存在を確認
    2. 移行情報の取得:
       - migration_idが指定された場合は単一の移行情報を取得
       - key_idが指定された場合は関連するすべての移行情報を取得（古い鍵と新しい鍵の両方）
    3. 進行中の移行の場合、進捗状況の更新
    4. ログ出力（移行状態取得イベント、migration_idまたはkey_idのみ）
    5. 移行情報の返却
    """
    pass
```

#### 4. 鍵バージョン管理機能（2 つの関数）

```python
def track_key_version(key_id: str, parent_key_id: str = None, version_metadata: dict = None) -> dict:
    """
    鍵バージョンを追跡し、バージョン間の関係を記録する

    Args:
        key_id: 現在の鍵ID（追跡対象）
        parent_key_id: 親鍵ID（この鍵がローテーションで生成された場合、省略可）
        version_metadata: バージョンに関するメタデータ（省略可）
          例: {
            "rotation_id": str,  # 関連するローテーション操作ID
            "reason": str,  # バージョン作成理由
            "algorithm_changes": dict,  # アルゴリズム変更詳細
            "custom_metadata": dict,  # カスタムメタデータ
          }

    Returns:
        バージョン追跡情報を含む辞書
        {
          "key_id": str,  # 鍵ID
          "version_id": str,  # バージョン識別子
          "parent_version_id": str,  # 親バージョン識別子（存在する場合）
          "version_number": int,  # バージョン番号（1から始まる連番）
          "creation_date": str,  # 作成日時（ISO 8601形式）
          "is_current": bool,  # 現在のバージョンかどうか
          "metadata": dict,  # 記録されたメタデータ
          "lineage": [  # バージョン系統（最新から最古まで）
            {"version_id": str, "creation_date": str},
            ... 他のバージョン ...
          ]
        }

    Raises:
        ValueError: key_idが存在しない場合
        ValueError: parent_key_idが指定され、存在しない場合
        ValueError: version_metadataの形式が無効な場合
        KeyManagementError: バージョン追跡に失敗した場合

    実装詳細:
    1. 引数の検証:
       - key_idの存在確認
       - parent_key_idが指定されている場合はその存在を確認
       - version_metadataの検証（指定されている場合）
    2. バージョン識別子の生成（UUID v4）
    3. 親バージョン情報の取得（parent_key_idが指定されている場合）
    4. バージョン番号の決定:
       - 親バージョンがある場合: 親バージョン番号 + 1
       - 親バージョンがない場合: 1（初期バージョン）
    5. バージョン系統の構築:
       - 親バージョンの系統情報の取得と拡張
    6. バージョン情報の保存（key_storageと連携）
    7. 鍵メタデータの更新（現在のバージョン情報を含める）
    8. ログ出力（バージョン追跡イベント、key_idと生成されたversion_idのみ）
    9. バージョン追跡情報の返却
    """
    pass

def list_key_versions(key_id: str, include_metadata: bool = False) -> list:
    """
    鍵の全バージョン履歴を取得する

    Args:
        key_id: バージョン履歴を取得する鍵のID
        include_metadata: 各バージョンのメタデータを含めるかどうか（デフォルト: False）

    Returns:
        バージョン情報のリスト（新しい順）
        [
          {
            "version_id": str,  # バージョン識別子
            "version_number": int,  # バージョン番号
            "creation_date": str,  # 作成日時（ISO 8601形式）
            "is_current": bool,  # 現在のバージョンかどうか
            "rotation_info": {  # ローテーション情報（存在する場合）
              "rotation_id": str,  # ローテーション操作ID
              "reason": str,  # ローテーション理由
            },
            "metadata": dict,  # バージョンメタデータ（include_metadataがTrueの場合）
            "key_id": str,  # このバージョンの鍵ID
          },
          ... 他のバージョン ...
        ]

    Raises:
        ValueError: key_idが存在しない場合
        KeyManagementError: バージョン情報の取得に失敗した場合

    実装詳細:
    1. 引数の検証:
       - key_idの存在確認
    2. 鍵の基本情報取得（key_manager.get_key_info()を使用）
    3. 鍵のバージョン系統情報の取得
    4. 各バージョンの詳細情報の収集:
       - バージョン識別子と番号
       - 作成日時
       - 現在のバージョンフラグ
       - ローテーション情報（該当する場合）
       - メタデータ（include_metadataがTrueの場合）
    5. 結果のソート（バージョン番号の降順）
    6. ログ出力（バージョン履歴取得イベント、key_idのみ）
    7. バージョン情報リストの返却
    """
    pass
```

## 🔍 完了の定義

以下の基準をすべて満たすことで、このタスクは「完了」とみなされます：

1. **実装完了の条件**:

   - [ ] `utils/key/key_rotation.py`が指定された仕様で実装されていること
   - [ ] ソースコードが単一責務の原則に従い、明確に構造化されていること
   - [ ] 全ての関数に適切なドキュメント（docstring）が付与されていること
   - [ ] コードレビューでの指摘事項がすべて解消されていること
   - [ ] 静的解析ツールによる警告がゼロであること

2. **機能完了の条件**:

   - [ ] 鍵ローテーションスケジュール管理機能が正確に動作すること
   - [ ] 鍵更新実行機能が正確に動作し、安全に鍵をローテーションできること
   - [ ] 安全な鍵移行機能が正確に動作し、データの整合性を維持できること
   - [ ] 鍵バージョン管理機能が正確に動作し、バージョン履歴を追跡できること
   - [ ] 既存の鍵管理機能（T15-T17）と適切に連携して動作すること

3. **テスト完了の条件**:

   - [ ] 単体テストのカバレッジが 95%以上であること
   - [ ] 各機能の正常系・異常系のテストケースが実装されていること
   - [ ] エッジケース（即時ローテーション、緊急ローテーション、移行中断など）のテストが実装されていること
   - [ ] 他の鍵管理コンポーネントとの統合テストが実装され、正常に動作することが確認されていること
   - [ ] 長期的な鍵ローテーションシナリオのテストが実装されていること

4. **ドキュメント完了の条件**:

   - [ ] 全ての関数に詳細なドキュメントが記載されていること
   - [ ] 機能の使用例とサンプルコードが提供されていること
   - [ ] 鍵ローテーションのベストプラクティスと推奨設定が文書化されていること
   - [ ] エラー処理と回復手順が文書化されていること
   - [ ] 後続タスク（T19、T20）との連携方法が説明されていること

5. **納品物件検証条件**:

   - [ ] `utils/key/key_rotation.py`
   - [ ] テストコード（`tests/utils/key/test_key_rotation.py`）
   - [ ] テスト用データと設定ファイル
   - [ ] CI/CD 設定への統合
   - [ ] コードのドキュメント

## 🧪 テスト対応方針

### テストケース概要

1. **鍵ローテーションスケジュール管理機能のテスト**:

   - 各種ローテーションタイプ（時間基準、使用回数基準、ハイブリッド、閾値基準）でのスケジュール作成テスト
   - スケジュール取得・更新のテスト
   - 無効なパラメータによるエラーケーステスト

2. **鍵更新実行機能のテスト**:

   - スケジュールに基づくローテーション実行テスト
   - 強制ローテーションテスト
   - 保留中ローテーション検出テスト
   - ローテーション失敗時の例外ハンドリングテスト

3. **安全な鍵移行機能のテスト**:

   - 異なる移行戦略（即時、漸進的、二重運用）のテスト
   - 既存データの再暗号化テスト
   - 移行中断とロールバックテスト
   - 移行状態の取得テスト

4. **鍵バージョン管理機能のテスト**:
   - バージョン追跡と系統構築テスト
   - バージョン履歴取得テスト
   - メタデータ管理テスト

### 単体テスト方針

- モックを活用して依存コンポーネント（`key_manager`, `key_storage`, `verify_key_quality`など）を分離
- パラメータバリエーションを使用した網羅的なテスト
- 正常系と異常系の両方をカバー
- 時間依存のテストには固定時間を使用

### 統合テスト方針

- 実際の鍵管理コンポーネント（T15-T17）との連携テスト
- エンドツーエンドのローテーションシナリオテスト
- パフォーマンステスト（大量の鍵や長期的なローテーションスケジュール）

### テストダブル方針

以下のモックやスタブを作成してテストを効率化：

- `key_manager`のモック（鍵生成・取得操作のシミュレート）
- `key_storage`のモック（鍵の保存・読込操作のシミュレート）
- `verify_key_quality`のスタブ（様々な鍵品質評価結果のシミュレート）
- 時間進行のモック（ローテーションスケジュールのタイミングテスト用）

## 🚀 実装ヒント

### 技術的考慮事項

- **安全な移行のためのアトミック操作**: 鍵ローテーション中に部分的な状態が発生しないよう、移行操作はできる限りアトミックに行ってください。障害が発生した場合は、一貫性のある状態にロールバックできるようにしてください。

- **パフォーマンスと可用性**: 特に大規模なデータセットに対するローテーション操作でも、システムのパフォーマンスと可用性が維持されるよう配慮してください。バックグラウンド処理や段階的移行などのテクニックを検討してください。

- **トランザクション安全性**: 複数のコンポーネントにまたがる操作（鍵の生成、バージョン更新、メタデータ更新など）はトランザクション的な整合性を保証し、部分的な更新状態が残らないようにしてください。

- **例外処理**: すべての操作で適切な例外処理を実装し、エラー発生時に適切な診断情報をログに記録してください。特に移行プロセス中の失敗は詳細に記録し、リカバリが可能な状態を維持してください。

### 実装のコツ

- 🧩 **関数の分離**: 10 個の関数が適切に責務分担されていることを確認してください。特にローテーションスケジュール管理と実際の鍵更新処理は明確に分離すると保守性が向上します。

- 🧩 **設定の柔軟性**: 様々なローテーション戦略やスケジュール定義をサポートするため、設定パラメータは十分に柔軟かつ拡張可能な設計にしてください。

- 🧩 **ログと監査**: セキュリティ監査の観点から、すべての鍵ローテーションイベントとその結果を適切にログに記録してください。ただし、ログに鍵自体の情報が漏れないよう注意してください。

- 🧩 **バックワードコンパティビリティ**: ローテーション後も古い鍵で暗号化されたデータを復号できるようにするため、鍵のバージョン管理と履歴追跡を正確に実装してください。

- 🧩 **三暗号方式の整合性**: Tri-Fusion アーキテクチャの三暗号方式（ラビットストリーム、準同型暗号、量子耐性レイヤー）間の整合性が維持されるよう、鍵のローテーションと移行をサポートしてください。

- 🧩 **第二回暗号解読キャンペーン対策**: 鍵ローテーション中の情報漏洩を防止するため、ローテーションプロセス自体が新たな攻撃ベクトルにならないよう注意深く設計してください。特に、ローテーション間隔や移行戦略に関する情報が漏れないようにしてください。

## 📚 参考資料

1. **NIST SP 800-57**: 暗号鍵管理のための推奨事項

   - [NIST Special Publication 800-57 Part 1 Revision 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
   - 特に第 8 章「鍵の状態と遷移」を参照してください

2. **OWASP Cryptographic Storage Cheat Sheet**: 暗号化ストレージのベストプラクティス

   - [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
   - 鍵ローテーションの実装方法と注意点に関する情報が含まれています

3. **Python Cryptography Library**: Python での暗号実装のベストプラクティス
   - [Python Cryptography](https://cryptography.io/en/latest/)
   - 鍵管理と安全な暗号操作に関する参考情報があります

## 📋 最終確認事項

この実装指示書に従って、鍵ローテーション機能を実装してください。タイムライン上の次のタスクは T19（量子乱数ソルト生成実装）であり、このタスクの機能と連携する必要があります。

実装上の疑問や問題がある場合は、すぐに質問してください。品質と安全性が最優先事項です。特に、ローテーションプロセス中のシステム可用性とデータ整合性の維持に注意を払ってください。

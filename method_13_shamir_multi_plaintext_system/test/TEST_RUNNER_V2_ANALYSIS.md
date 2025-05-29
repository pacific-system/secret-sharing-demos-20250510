# テストランナー V2 現状分析ドキュメント

## 1 メイン処理シーケンス

1. **実行環境確定** - プロセス冒頭で test_runner_V2.py の絶対パス取得（行 32-37）
   - 1.1 **test_runner_V2.py 絶対パス取得** - os.path.abspath(**file**)で TEST_RUNNER_V2_FILE_PATH 取得
   - 1.2 **実行ディレクトリ導出** - os.path.dirname()で TEST_RUNNER_V2_DIR 取得
   - 1.3 **カレントディレクトリ変更** - os.chdir(TEST_RUNNER_V2_DIR)で実行環境を確定
2. **ログ設定初期化** - setup_logger()でログ環境構築（行 47、実行環境確定後）
   - 2.1 **ログディレクトリ作成** - logs/ディレクトリの自動作成（確定された実行環境下）
   - 2.2 **ログファイル生成** - test*log*{timestamp}.log ファイル作成
   - 2.3 **ハンドラー設定** - コンソール出力とファイル出力の両方設定
3. **TestRunnerV2 インスタンス生成** - main()で TestRunnerV2()初期化（行 182）
   - 3.1 **ファイルマネージャー初期化** - TestResultFileManager()生成（行 54）
   - 3.2 **テスト実行器初期化** - TestExecutor(file_manager)生成（行 55）
   - 3.3 **分析実行器初期化** - AnalysisExecutor(file_manager)生成（行 56）
4. **テスト実行開始ログ** - "テスト実行を開始します"メッセージ出力（行 68）
   - 4.1 **実行環境情報ログ** - TEST_RUNNER_V2_DIR の実行環境をログ出力（行 69）
   - 4.2 **絶対パス情報ログ** - TEST_RUNNER_V2_FILE_PATH の絶対パスをログ出力（行 70）
5. **ファイル永続化初期化** - file_manager.initialize_new_execution()実行（行 73）
   - 5.1 **UUID 生成** - 36 文字の UUID 生成
   - 5.2 **タイムスタンプ生成** - YYYYMMDD_HHMMSS 形式
   - 5.3 **ファイル名決定** - test*results*{UUID}\_{TIMESTAMP}.json
   - 5.4 **results ディレクトリ作成** - results/ディレクトリの自動作成
   - 5.5 **初期 JSON ファイル書き込み** - 実行開始時の初期化データ保存
6. **設定ファイル読み込み** - load_config()実行、失敗時は即座終了（行 76-81）
   - 6.1 **設定ファイル読み込み失敗時の即座終了** - config が None の場合、エラーログ出力と file_manager.mark_error()実行後、sys.exit(1)で即座終了
7. **設定データファイル保存** - file_manager.update_config_data(config)実行（行 84-85）
   - 7.1 **設定データ構造化** - ConfigData オブジェクト生成
   - 7.1.1 **test_repeat_count フォールバック** - config.get('reporting', {}).get('test_repeat_count', 1) でデフォルト値 1 を採用
   - 7.1.2 **システムパラメータ未設定時の None 採用** - partition_size, active_shares 等が設定ファイルにない場合は None を採用
   - 7.2 **JSON ファイル更新** - 設定ファイル読み込み完了をファイルに記録
8. **テストケース検出** - TestCaseDiscoverer().discover_test_cases()実行（行 88-94）
   - 8.0 **TestCaseDiscoverer インスタンス生成** - discoverer = TestCaseDiscoverer()でインスタンス化（行 88）
   - 8.0.1 **テスト用絶対パス取得** - TestCaseDiscoverer.**init**()内で**file**を使用して test_runner_V2_test_executor.py の絶対パス取得
   - 8.0.2 **テストベースディレクトリ導出** - os.path.dirname()で test ディレクトリの絶対パスを導出して self.base_dir に設定
   - 8.1 **ディレクトリスキャン** - test_cases/配下の 3 ディレクトリを検索
     - 8.1.1 **crypto_storage_creation 検索** - test*cases/crypto_storage_creation/test*\*.py ファイルを検索
       - 8.1.1.1 **test_cc_001_basic_creation.py 検出** - test_cc_001_basic_creation.py ファイルを動的インポート
     - 8.1.2 **crypto_storage_update 検索** - test*cases/crypto_storage_update/test*\*.py ファイルを検索
       - 8.1.2.1 **該当ファイルなしのスキップ処理** - test\_\*.py ファイルが存在しない場合はスキップ
     - 8.1.3 **crypto_storage_read 検索** - test*cases/crypto_storage_read/test*\*.py ファイルを検索
       - 8.1.3.1 **該当ファイルなしのスキップ処理** - test\_\*.py ファイルが存在しない場合はスキップ
   - 8.1.4 **ディレクトリ未存在時のスキップ処理** - os.path.exists()でディレクトリが存在しない場合は continue でスキップ
   - 8.2 **動的モジュールインポート** - importlib.import_module()でロード
   - 8.2.1 **モジュールロード失敗時の継続処理** - Exception 発生時は log_error()でエラー記録後、処理継続
   - 8.2.2 **クロスプラットフォーム対応** - os.sep を使用して Windows/Linux 両対応のモジュール名生成
   - 8.3 **クラス検査** - BaseTest 継承クラスを検出
   - 8.4 **インスタンス化と ID 検証** - test_id 属性の有効性確認
   - 8.5 **テストケース未発見時の即座終了** - test_cases が空の場合、エラーログ出力と file_manager.mark_error()実行後、sys.exit(1)で即座終了
9. **テストケース数メタデータ更新** - file_manager.update_metadata()実行（行 96）
   - 9.1 **検出テストケース一覧ログ** - 検出されたテストケースのキー一覧をログ出力（行 97）
10. **分析モジュール検出** - AnalyzerDiscoverer().discover_analyzers()実行（行 100-106）
    - 10.0 **AnalyzerDiscoverer インスタンス生成** - analyzer_discoverer = AnalyzerDiscoverer()でインスタンス化（行 100）
    - 10.0.1 **分析用絶対パス取得** - AnalyzerDiscoverer.**init**()内で**file**を使用して test_runner_V2_analysis_executor.py の絶対パス取得
    - 10.0.2 **分析ベースディレクトリ導出** - os.path.dirname()で test ディレクトリの絶対パスを導出して self.base_dir に設定
    - 10.1 **分析ディレクトリスキャン** - analysis/ディレクトリを検索
      - 10.1.1 **key_length_analyzer.py 検出** - key_length_analyzer.py ファイルを動的インポート
      - 10.1.2 **map_intersection_analyzer.py 検出** - map_intersection_analyzer.py ファイルを動的インポート
    - 10.1.3 **分析ディレクトリ未存在時の空辞書返却** - analysis/ディレクトリが存在しない場合は空の analyzers 辞書を返却
    - 10.2 **アナライザークラス検出** - \*Analyzer で終わるクラス名を検索
    - 10.3 **name 属性検証** - 有効な name 属性を持つかチェック
    - 10.4 **分析モジュール未発見時の警告継続** - analyzers が空の場合は"分析なしでテスト実行を継続します"警告ログ出力後、処理継続
    - 10.5 **検出分析モジュール一覧ログ** - 検出された分析モジュールのキー一覧をログ出力（行 104）
    - 10.6 **クロスプラットフォーム対応** - os.sep を使用して Windows/Linux 両対応のモジュール名生成
11. **分析モジュール数メタデータ更新** - file_manager.update_metadata()実行（行 107）
12. **テスト実行（JSON ファイル専用）** - test_executor.run_tests(test_cases)実行（行 110）
    - 12.0 **メモリ上データ排除** - メモリ上のデータを返さず、JSON ファイルのみに保存
    - 12.1 **繰り返し回数設定** - 設定ファイルから読み込み（1-10 回制限）
    - 12.1.1 **repeat_count デフォルト値採用** - 設定ファイルが読み込めない場合は repeat_count = 1 をデフォルト値として採用
    - 12.1.2 **repeat_count 上限制限フォールバック** - repeat_count > 10 の場合は 10 に制限、< 1 の場合は 1 に制限
    - 12.2 **イテレーションループ開始** - 指定回数分の繰り返し実行
    - 12.3 **テストケース有効性チェック** - is_test_enabled()で確認
    - 12.3.1 **無効テストのスキップ処理** - is_test_enabled()が False の場合は continue でスキップ
    - 12.4 **テストインスタンス生成** - 各テストクラスのインスタンス化
    - 12.5 **個別テスト実行** - test_instance.run()呼び出し
    - 12.5.1 **テスト実行失敗時のエラー結果生成** - Exception 発生時は{"test_id": test_id, "success": False, "error": str(e)}の失敗結果を生成
    - 12.6 **CLI レスポンス受信記録** - file_manager.update_cli_response_received()実行
    - 12.7 **パスワード読み込み記録** - file_manager.update_password_loaded()実行
    - 12.8 **テスト結果ログ保存** - log_test_result()でログファイルに永続化
    - 12.8.1 **success フィールドのデフォルト値採用** - result.get("success", False)で success フィールドが存在しない場合は False を採用
    - 12.9 **イテレーション結果ファイル保存** - file_manager.add_iteration_result()実行
    - 12.9.1 **execution_time デフォルト値採用** - result.get("execution_time", 0.0)で実行時間が取得できない場合は 0.0 を採用
13. **分析実行（JSON ファイル専用）** - analysis_executor.run_analysis_from_json_file(analyzers)実行（行 113-114）
    - 13.0 **JSON ファイルからデータ読み込み** - file_manager.get_execution_data()で JSON ファイルから実行データを取得
    - 13.1 **分析用データ構築** - JSON データから latest_test_results と all_test_results を構築
    - 13.2 **分析有効性チェック** - is_analysis_enabled()で確認
    - 13.3 **分析インスタンス生成** - analyzer_class()でインスタンス化
    - 13.4 **map_intersection 特別処理** - MapIntersectionAnalyzer.analyze_with_file_tracking()実行
    - 13.5 **比較一回ごとファイル記録** - file_manager.add_map_comparison()実行
    - 13.6 **その他分析結果ファイル記録** - file_manager.add_other_analysis_result()実行
14. **レポート生成（JSON ファイル専用）** - \_generate_and_save_report_from_json()実行（行 117）
    - 14.0 **JSON ファイルからデータ読み込み** - file_manager.get_current_file_path()で JSON ファイルパスを取得
    - 14.1 **レポート生成開始記録** - file_manager.start_report_generation()実行
    - 14.2 **JSON ファイルベースレポート生成** - generate_report_from_json_file()で JSON ファイルからレポート生成
    - 14.3 **データ変換処理** - JSON データを既存の generate_report()関数で使用できる形式に変換
    - 14.4 **レポート保存** - save_report()実行
    - 14.4.1 **レポート生成失敗時の継続処理** - report が None または False の場合は log_error()でエラー記録と file_manager.complete_report_generation(None)実行後、処理継続
    - 14.4.2 **レポート保存失敗時の継続処理** - save_report()が False を返した場合は log_error()でエラー記録と file_manager.complete_report_generation(None)実行後、処理継続
    - 14.5 **レポート生成完了記録** - file_manager.complete_report_generation()実行
    - 14.5.1 **レポート生成例外時の継続処理** - Exception 発生時は log_error()でエラー記録、try-except 内で file_manager.complete_report_generation(None)実行後、処理継続
15. **テスト完了ログ** - "テスト実行が完了しました"メッセージ出力（行 120）
16. **結果集計（JSON ファイル専用）** - \_count_results_from_json()で成功数と失敗数をカウント（行 123）
    - 16.1 **JSON ファイルからデータ取得** - file_manager.get_execution_data()で JSON ファイルから実行データを取得
    - 16.2 **最新イテレーション結果取得** - 最新のイテレーション結果から成功・失敗数をカウント
    - 16.3 **success フィールドのデフォルト値採用** - test_result.success で成功・失敗を判定
17. **結果サマリーログ** - 合計/成功/失敗数を出力（行 125）
18. **終了コード決定** - テスト成功/失敗で 0/1 を返却（行 128）
19. **プロセス終了** - sys.exit()で main()の戻り値を終了コードに設定（行 188）
    - 19.1 **メイン例外時の終了コード 1 返却** - run()メソッドで Exception 発生時は log_error()と try-except 内で file_manager.mark_error()実行後、終了コード 1 を返却

## 2 実装不足・問題点

### 2.1 ✅ レポート生成関数の引数不整合（修正済み）

- ~~問題: 行 152 で generate_report()に result_file_path を渡している~~
- ~~実態: utils/report_generator.py の generate_report()は(test_results, analysis_results, all_test_results)を期待~~
- ~~影響: レポート生成が失敗する可能性~~
- **修正済み**: generate_report_from_json_file()を新規実装し、JSON ファイルからデータを読み込んでレポート生成

### 2.2 ✅ JSON ファイルを唯一のデータ源泉とする適正化（実装済み）

- ~~問題: ファイルに永続化したデータをレポート生成時に活用する仕組みが不完全~~
- ~~実態: generate_report()が JSON ファイルパスを受け取っても、ファイルからデータを読み込む処理が未実装~~
- ~~影響: 永続化したデータがレポートに反映されない~~
- **実装済み**:
  - **メモリ上データ排除**: test_executor.run_tests()はメモリ上のデータを返さず、JSON ファイルのみに保存
  - **JSON ファイル専用分析**: analysis_executor.run_analysis_from_json_file()で JSON ファイルからデータを読み込んで分析実行
  - **JSON ファイル専用レポート**: generate_report_from_json_file()で JSON ファイルからレポート生成
  - **データ整合性確保**: 常に JSON ファイルを唯一のデータ源泉として使用し、メモリ上のオブジェクトは参照・保存しない
- **設計の妥当性**: JSON ファイルを唯一のデータ源泉とすることで、データの不整合を防止し、デバッグ性と信頼性を向上

### 2.3 ✅ エラーハンドリングの不完全性（部分修正済み）

- ~~問題: 各コンポーネント間の連携でエラーが発生した場合の処理が不十分~~
- ~~実態: file_manager.mark_error()は呼ばれるが、部分的な成功データの活用方法が未定義~~
- ~~影響: 途中でエラーが発生した場合、それまでの結果が無駄になる~~
- **部分修正済み**: try-except 内でのエラーハンドリングを強化、レポート生成失敗時の継続処理を実装
- **残課題**: 部分的成功時のレポート生成機能は未実装

### 2.4 ✅ 互換性維持の複雑性（適正化済み）

- ~~問題: 既存の all_test_results 形式との互換性維持のため、データ変換処理が複雑~~
- ~~実態: TestExecutor で互換性用のデータ変換を行っているが、パフォーマンス影響あり~~
- ~~影響: メモリ使用量増加、処理速度低下~~
- **適正化済み**:
  - **JSON ファイル構造に統一**: 全処理を JSON ファイル構造に合わせて適正化
  - **メモリ使用量削減**: メモリ上のデータ保持を排除し、メモリ使用量を大幅削減
  - **処理速度向上**: 不要なデータ変換処理を削除し、処理速度を向上
  - **データ変換の最適化**: generate_report_from_json_file()内でのみ必要最小限のデータ変換を実行

### 2.5 ✅ フォールバック処理の明示化（実装済み）

- **実装済み**: 各種フォールバック処理を明示的に実装
  - 設定ファイル読み込み失敗時の即座終了
  - テストケース未発見時の即座終了
  - 分析モジュール未発見時の継続処理
  - JSON ファイルからのデータ取得失敗時のフォールバック処理
  - レポート生成失敗時の継続処理

## 3 データ構造

### 3.1 TestExecutionData 構造（実際の実装）

```json
{
  "metadata": {
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "execution_start_time": "2025-01-10T14:30:22.123456",
    "last_updated": "2025-01-10T14:35:45.789012",
    "status": "running|completed|error",
    "config_loaded": true,
    "test_cases_discovered": 3,
    "analyzers_discovered": 2
  },
  "config_data": {
    "test_repeat_count": 5,
    "partition_size": 1024,
    "active_shares": 3,
    "raw_config": {...}
  },
  "test_execution": {
    "iterations": [
      {
        "iteration": 1,
        "start_time": "2025-01-10T14:31:00.000000",
        "test_results": {
          "test_id": {
            "test_id": "test_id",
            "success": true,
            "storage_filepath": "/path/to/encrypted/file",
            "password_a": "...",
            "password_b": "...",
            "cli_response_received": "2025-01-10T14:31:15.456",
            "password_loaded": "2025-01-10T14:31:16.123"
          }
        },
        "completed_time": "2025-01-10T14:32:00.000000"
      }
    ]
  },
  "analysis_execution": {
    "map_intersection": {
      "start_time": "2025-01-10T14:33:00.000000",
      "a_map_comparisons": [
        {"comparison": "1-1", "timestamp": "...", "rate": 100.0},
        {"comparison": "1-2", "timestamp": "...", "rate": 85.5}
      ],
      "b_map_comparisons": [...],
      "ab_map_comparisons": [...],
      "final_results": {...},
      "completed_time": "2025-01-10T14:34:00.000000"
    },
    "other_analyses": {...}
  },
  "report_generation": {
    "start_time": "2025-01-10T14:35:00.000000",
    "completed_time": "2025-01-10T14:35:30.000000",
    "report_filename": "test_report_20250110_143530.md"
  }
}
```

## 4 ファイル永続化仕様

### 4.1 保存場所・命名規則

- 保存ディレクトリ: results/
- ファイル名: test*results*{UUID}\_{TIMESTAMP}.json
- UUID: 36 文字の完全版
- TIMESTAMP: YYYYMMDD_HHMMSS 形式

### 4.2 書き込みタイミング（実装済み）

- ✅ 実行開始時（初期化）
- ✅ 設定ファイル読み込み完了
- ✅ テストケース検出完了
- ✅ 分析モジュール検出完了
- ✅ CLI レスポンス受信時
- ✅ パスワード読み込み時
- ✅ 各イテレーション完了時
- ✅ map_intersection 比較一回ごと
- ✅ 各分析完了時
- ✅ レポート生成開始/完了時

## 5 コンポーネント分割状況

### 5.1 実装済みコンポーネント

- **test_runner_V2.py** (178 行) - メイン処理
- **test_runner_V2_data_structures.py** (232 行) - データ構造定義
- **test_runner_V2_file_manager.py** (343 行) - ファイル永続化管理
- **test_runner_V2_test_executor.py** (276 行) - テスト実行処理
- **test_runner_V2_analysis_executor.py** (260 行) - 分析実行処理

### 5.2 未実装・要修正コンポーネント

- report_generator.py 修正 - JSON ファイルパス対応、ファイル読み込み機能追加
- エラー回復機能 - 部分的成功時のレポート生成
- パフォーマンス最適化 - 互換性維持のためのデータ変換処理最適化

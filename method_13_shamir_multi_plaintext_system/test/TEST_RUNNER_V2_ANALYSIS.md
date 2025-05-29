# テストランナー V2 現状分析ドキュメント

## 1 メイン処理シーケンス

1. **ログ設定初期化** - setup_logger()でログ環境構築（行 42）
   - 1.1 **ログディレクトリ作成** - logs/ディレクトリの自動作成
   - 1.2 **ログファイル生成** - test*log*{timestamp}.log ファイル作成
   - 1.3 **ハンドラー設定** - コンソール出力とファイル出力の両方設定
2. **TestRunnerV2 インスタンス生成** - main()で TestRunnerV2()初期化（行 172）
   - 2.1 **ファイルマネージャー初期化** - TestResultFileManager()生成（行 49）
   - 2.2 **テスト実行器初期化** - TestExecutor(file_manager)生成（行 50）
   - 2.3 **分析実行器初期化** - AnalysisExecutor(file_manager)生成（行 51）
3. **テスト実行開始ログ** - "テスト実行を開始します"メッセージ出力（行 61）
4. **ファイル永続化初期化** - file_manager.initialize_new_execution()実行（行 64）
   - 4.1 **UUID 生成** - 36 文字の UUID 生成
   - 4.2 **タイムスタンプ生成** - YYYYMMDD_HHMMSS 形式
   - 4.3 **ファイル名決定** - test*results*{UUID}\_{TIMESTAMP}.json
   - 4.4 **results ディレクトリ作成** - results/ディレクトリの自動作成
   - 4.5 **初期 JSON ファイル書き込み** - 実行開始時の初期化データ保存
5. **設定ファイル読み込み** - load_config()実行、失敗時は即座終了（行 67-72）
6. **設定データファイル保存** - file_manager.update_config_data(config)実行（行 75-76）
   - 6.1 **設定データ構造化** - ConfigData オブジェクト生成
   - 6.2 **設定値フォールバック処理** - test_repeat_count=config.get('reporting', {}).get('test_repeat_count', 1)でデフォルト値 1 を採用、各システムパラメータも get()で None 許容
   - 6.3 **JSON ファイル更新** - 設定ファイル読み込み完了をファイルに記録
7. **テストケース検出** - TestCaseDiscoverer().discover_test_cases()実行（行 79-85）
   - 7.1 **ディレクトリスキャン** - test_cases/配下の 3 ディレクトリを検索
   - 7.2 **ディレクトリ未存在時フォールバック** - os.path.exists()でディレクトリが存在しない場合は continue で次のディレクトリへ、警告ログのみ出力
   - 7.3 **ファイルパターンマッチ** - test\_\*.py ファイルを検索
   - 7.4 **動的モジュールインポート** - importlib.import_module()でロード
   - 7.5 **モジュールロード失敗時フォールバック** - Exception 発生時は log_error()でエラーログ出力のみ、処理継続
   - 7.6 **クラス検査** - BaseTest 継承クラスを検出
   - 7.7 **インスタンス化と ID 検証** - test_id 属性の有効性確認
8. **テストケース数メタデータ更新** - file_manager.update_metadata()実行（行 87）
9. **分析モジュール検出** - AnalyzerDiscoverer().discover_analyzers()実行（行 90-94）
   - 9.1 **分析ディレクトリスキャン** - analysis/ディレクトリを検索
   - 9.2 **分析ディレクトリ未存在時フォールバック** - os.path.exists()で analysis/ディレクトリが存在しない場合は空辞書{}を返却、警告ログのみ出力
   - 9.3 **アナライザーファイル検索** - \*\_analyzer.py パターンマッチ
   - 9.4 **アナライザーロード失敗時フォールバック** - Exception 発生時は log_error()でエラーログ出力のみ、処理継続
   - 9.5 **アナライザークラス検出** - \*Analyzer で終わるクラス名を検索
   - 9.6 **name 属性検証** - 有効な name 属性を持つかチェック
10. **分析モジュール数メタデータ更新** - file_manager.update_metadata()実行（行 96）
    - 10.1 **分析モジュール未発見時の継続処理** - analyzers={}の場合でも log_warning()のみで処理継続、analyzers_discovered=0 で記録
11. **テスト実行** - test_executor.run_tests(test_cases)実行（行 99）
    - 11.1 **繰り返し回数フォールバック処理** - repeat_count = 1 をデフォルト値として設定、設定ファイルから取得失敗時は 1 回実行
    - 11.2 **繰り返し回数範囲制限フォールバック** - repeat_count > 10 の場合は 10 に制限、repeat_count < 1 の場合は 1 に制限、警告ログ出力
    - 11.3 **イテレーションループ開始** - 指定回数分の繰り返し実行
    - 11.4 **テストケース有効性チェック** - is_test_enabled()で確認
    - 11.5 **無効テスト時フォールバック** - is_test_enabled()=false の場合は continue でスキップ、情報ログのみ出力
    - 11.6 **テストインスタンス生成** - 各テストクラスのインスタンス化
    - 11.7 **個別テスト実行** - test_instance.run()呼び出し
    - 11.8 **テスト実行失敗時フォールバック** - Exception 発生時は{"test_id": test_id, "success": False, "error": str(e)}の失敗結果を生成
    - 11.9 **CLI レスポンス受信記録** - file_manager.update_cli_response_received()実行
    - 11.10 **パスワード読み込み記録** - file_manager.update_password_loaded()実行
    - 11.11 **結果取得フォールバック処理** - result.get("success", False)で success 未定義時は False を採用
    - 11.12 **テスト結果ログ保存** - log_test_result()でログファイルに永続化
    - 11.13 **イテレーション結果ファイル保存** - file_manager.add_iteration_result()実行
12. **最新テスト結果取得** - test_executor.get_latest_test_results()実行（行 102）
    - 12.1 **実行データ未存在時フォールバック** - execution_data 未存在または iterations 空の場合は空辞書{}を返却
13. **分析実行** - analysis_executor.run_analysis()実行（行 103-106）
    - 13.1 **分析有効性チェック** - is_analysis_enabled()で確認
    - 13.2 **無効分析時フォールバック** - is_analysis_enabled()=false の場合は continue でスキップ、情報ログのみ出力
    - 13.3 **分析インスタンス生成** - analyzer_class()でインスタンス化
    - 13.4 **map_intersection 特別処理** - MapIntersectionAnalyzer.analyze_with_file_tracking()実行
    - 13.5 **分析実行失敗時フォールバック** - Exception 発生時は{"name": analyzer_id, "pass": False, "error": str(e)}のエラー結果を生成
    - 13.6 **分析結果取得フォールバック処理** - result.get("pass", False)で pass 未定義時は False を採用
    - 13.7 **比較一回ごとファイル記録** - file_manager.add_map_comparison()実行
    - 13.8 **比較結果記録失敗時フォールバック** - 比較結果記録で Exception 発生時は warning ログのみ出力、処理継続
    - 13.9 **その他分析結果ファイル記録** - file_manager.add_other_analysis_result()実行
14. **レポート生成** - \_generate_and_save_report()実行（行 109）
    - 14.1 **レポート生成開始記録** - file_manager.start_report_generation()実行
    - 14.2 **レポート生成関数の引数不整合** - generate_report()に result_file_path を渡しているが、実際の関数は all_test_results を期待
    - 14.3 **レポート生成失敗時フォールバック** - report=None の場合は log_error()でエラーログのみ出力、処理継続
    - 14.4 **レポート保存失敗時フォールバック** - save_report()=False の場合は log_error()でエラーログのみ出力、処理継続
    - 14.5 **レポート保存** - save_report()実行
    - 14.6 **レポート生成完了記録** - file_manager.complete_report_generation()実行
    - 14.7 **レポート生成例外時フォールバック** - Exception 発生時は log_error()でエラーログのみ出力、処理継続
15. **テスト完了ログ** - "テスト実行が完了しました"メッセージ出力（行 112）
16. **結果集計** - 成功数と失敗数をカウント（行 115-116）
    - 16.1 **結果集計フォールバック処理** - result.get("success", False)で各テスト結果の success 未定義時は False を採用
17. **結果サマリーログ** - 合計/成功/失敗数を出力（行 118）
18. **終了コード決定** - テスト成功/失敗で 0/1 を返却（行 121）
19. **メイン例外時フォールバック** - run()メソッド全体で Exception 発生時は log_error()と file_manager.mark_error()実行後、return 1 で失敗終了
20. **プロセス終了** - sys.exit()で main()の戻り値を終了コードに設定（行 175）

## 2 実装不足・問題点

### 2.1 レポート生成関数の引数不整合

- 問題: 行 152 で generate_report()に result_file_path を渡している
- 実態: utils/report_generator.py の generate_report()は(test_results, analysis_results, all_test_results)を期待
- 影響: レポート生成が失敗する可能性
- 対策: generate_report()の呼び出しを修正するか、report_generator.py を更新

### 2.2 JSON ファイルからのデータ読み込み機能未実装

- 問題: ファイルに永続化したデータをレポート生成時に活用する仕組みが不完全
- 実態: generate_report()が JSON ファイルパスを受け取っても、ファイルからデータを読み込む処理が未実装
- 影響: 永続化したデータがレポートに反映されない
- 対策: report_generator.py に JSON ファイル読み込み機能を追加

### 2.3 エラーハンドリングの不完全性

- 問題: 各コンポーネント間の連携でエラーが発生した場合の処理が不十分
- 実態: file_manager.mark_error()は呼ばれるが、部分的な成功データの活用方法が未定義
- 影響: 途中でエラーが発生した場合、それまでの結果が無駄になる
- 対策: 部分的成功時のレポート生成機能を追加

### 2.4 互換性維持の複雑性

- 問題: 既存の all_test_results 形式との互換性維持のため、データ変換処理が複雑
- 実態: TestExecutor で互換性用のデータ変換を行っているが、パフォーマンス影響あり
- 影響: メモリ使用量増加、処理速度低下
- 対策: 段階的な移行計画の策定

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

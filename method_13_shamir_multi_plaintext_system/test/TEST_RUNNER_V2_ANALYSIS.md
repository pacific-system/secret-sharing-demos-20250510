# テストランナー V2 現状分析ドキュメント

## 1 メイン処理シーケンス

1. **実行環境確定** - プロセス冒頭で test_runner_V2.py の絶対パス取得（行 32-37）
   - 1.1 **test_runner_V2.py 絶対パス取得** - os.path.abspath(**file**)で TEST_RUNNER_V2_FILE_PATH 取得（行 32）
   - 1.2 **実行ディレクトリ導出** - os.path.dirname()で TEST_RUNNER_V2_DIR 取得（行 33）
   - 1.3 **カレントディレクトリ変更** - os.chdir(TEST_RUNNER_V2_DIR)で実行環境を確定（行 36）
2. **ログ設定初期化** - setup_logger()でログ環境構築（行 47、実行環境確定後）
   - 2.1 **ログディレクトリパス決定** - test_runner_V2.py の絶対パスを基準にログディレクトリを決定
     - 2.1.1 **test_logger.py 絶対パス取得** - utils/test_logger.py で os.path.abspath(**file**) により自身の絶対パス取得
     - 2.1.2 **utils ディレクトリ導出** - os.path.dirname(current_file) で utils/ ディレクトリパス取得
     - 2.1.3 **test ディレクトリ導出** - os.path.dirname(utils_dir) で test/ ディレクトリパス取得
     - 2.1.4 **logs ディレクトリ決定** - os.path.join(test_dir, "logs") で test/logs/ パス決定
     - 2.1.5 **正確なパス確定** - `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_13_shamir_multi_plaintext_system/test/logs/` として確定
   - 2.2 **ログディレクトリ作成** - logs/ ディレクトリの自動作成（確定された実行環境下）
   - 2.3 **ログファイル生成** - test*log*{timestamp}.log ファイル作成
   - 2.4 **ハンドラー設定** - コンソール出力とファイル出力の両方設定
   - 2.5 **ログパス確認ログ出力** - "ロガーを設定しました: {log_file_path}" でログファイルの正確なパスを確認
3. **TestRunnerV2 インスタンス生成** - main()で TestRunnerV2()初期化（行 342）
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
   - 5.6 **結果ファイルパス取得** - result_file_path 変数に格納（行 73）
   - 5.7 **初期化完了ログ** - "結果ファイルを初期化しました: {result_file_path}"ログ出力（行 74）
6. **設定ファイル読み込み** - load_config()実行、失敗時は即座終了（行 77-82）
   - 6.1 **設定ファイル読み込み実行** - config = load_config()で設定データ取得（行 77）
   - 6.2 **設定ファイル読み込み失敗時の即座終了** - if not config:で None 判定（行 78）
   - 6.3 **エラーメッセージ生成** - error_msg = "設定ファイルの読み込みに失敗しました"（行 79）
   - 6.4 **エラーログ出力** - log_error(error_msg)実行（行 80）
   - 6.5 **ファイルマネージャーエラー記録** - self.file_manager.mark_error(error_msg)実行（行 81）
   - 6.6 **プロセス即座終了** - sys.exit(1)で終了コード 1 で即座終了（行 82）
7. **設定データファイル保存** - file_manager.update_config_data(config)実行（行 85-86）
   - 7.1 **設定データ構造化** - ConfigData オブジェクト生成
   - 7.1.1 **test_repeat_count フォールバック** - config.get('reporting', {}).get('test_repeat_count', 1) でデフォルト値 1 を採用
   - 7.1.2 **システムパラメータ未設定時の None 採用** - partition_size, active_shares 等が設定ファイルにない場合は None を採用
   - 7.2 **JSON ファイル更新** - 設定ファイル読み込み完了をファイルに記録
   - 7.3 **設定記録完了ログ** - "設定ファイルをファイルに記録しました"ログ出力（行 86）
8. **テストケース検出** - TestCaseDiscoverer().discover_test_cases()実行（行 89-95）
   - 8.0 **TestCaseDiscoverer インスタンス生成** - discoverer = TestCaseDiscoverer()でインスタンス化（行 89）
   - 8.0.1 **テスト用絶対パス取得** - TestCaseDiscoverer.**init**()内で**file**を使用して test_runner_V2_test_executor.py の絶対パス取得
   - 8.0.2 **テストベースディレクトリ導出** - os.path.dirname()で test ディレクトリの絶対パスを導出して self.base_dir に設定
   - 8.1 **テストケース検出実行** - test_cases = discoverer.discover_test_cases()でテストケース辞書取得（行 90）
   - 8.2 **テストケース未発見時の即座終了** - if not test_cases:で空判定（行 91）
   - 8.3 **エラーメッセージ生成** - error_msg = "テストケースが見つかりませんでした"（行 92）
   - 8.4 **エラーログ出力** - log_error(error_msg)実行（行 93）
   - 8.5 **ファイルマネージャーエラー記録** - self.file_manager.mark_error(error_msg)実行（行 94）
   - 8.6 **プロセス即座終了** - sys.exit(1)で終了コード 1 で即座終了（行 95）
9. **テストケース数メタデータ更新** - file_manager.update_metadata()実行（行 98）
   - 9.1 **検出テストケース数記録** - test_cases_discovered=len(test_cases)でテストケース数をメタデータに記録（行 98）
   - 9.2 **検出テストケース一覧ログ** - "検出されたテストケース: {list(test_cases.keys())}"ログ出力（行 99）
10. **分析モジュール検出** - AnalyzerDiscoverer().discover_analyzers()実行（行 102-108）
    - 10.0 **AnalyzerDiscoverer インスタンス生成** - analyzer_discoverer = AnalyzerDiscoverer()でインスタンス化（行 102）
    - 10.0.1 **分析用絶対パス取得** - AnalyzerDiscoverer.**init**()内で**file**を使用して test_runner_V2_analysis_executor.py の絶対パス取得
    - 10.0.2 **分析ベースディレクトリ導出** - os.path.dirname()で test ディレクトリの絶対パスを導出して self.base_dir に設定
    - 10.1 **分析モジュール検出実行** - analyzers = analyzer_discoverer.discover_analyzers()で分析モジュール辞書取得（行 103）
    - 10.2 **分析モジュール未発見時の継続処理** - if not analyzers:で空判定（行 104）
    - 10.3 **継続警告ログ出力** - "分析モジュールが見つかりませんでした。分析なしでテスト実行を継続します。"警告ログ出力（行 106）
    - 10.4 **分析モジュール発見時のログ出力** - else:ブロックで"検出された分析モジュール: {list(analyzers.keys())}"ログ出力（行 108）
11. **分析モジュール数メタデータ更新** - file_manager.update_metadata()実行（行 111）
    - 11.1 **検出分析モジュール数記録** - analyzers_discovered=len(analyzers)で分析モジュール数をメタデータに記録（行 111）
12. **テスト実行（JSON ファイル専用）** - test_executor.run_tests(test_cases)実行（行 114）
    - 12.0 **メモリ上データ排除** - メモリ上のデータを返さず、JSON ファイルのみに保存
    - 12.1 **テスト実行メソッド呼び出し** - self.test_executor.run_tests(test_cases)で戻り値なしのテスト実行（行 114）
    - 12.1.1 **イテレーションループ開始** - test_runner_V2_test_executor.py 行 155 で repeat_count 回のループ開始
      - **ループ範囲**: 行 155 `for iteration in range(repeat_count):` から 行 202 `self.file_manager.add_iteration_result(iteration + 1, test_results)` まで
      - **ループ変数**: iteration（0 から repeat_count-1 まで）
      - **ループ継続・終了判断ポイント**:
        - **継続判断**: `iteration < repeat_count` の条件でループ継続（Python の range() による自動制御）
        - **正常終了**: repeat_count 回の実行完了後、自動的にループ終了
        - **異常終了**: 個別テストの例外は catch されるが、**イテレーション全体を停止する仕組みは未実装**
        - **早期終了条件**: 現在は実装されていない（全イテレーション強制実行）
      - **実装不備**:
        - ❌ **致命的エラー時の早期終了機能なし**: ファイルマネージャーエラーやシステムエラー時もループ継続
        - ❌ **ユーザー中断機能なし**: Ctrl+C 等での安全な中断処理が未実装
        - ❌ **リソース枯渇時の停止機能なし**: メモリ不足やディスク容量不足時の自動停止なし
      - **ループ内処理概要**:
        - 行 156: イテレーション開始ログ出力
        - 行 157: test_results = {} でイテレーション用結果辞書初期化
        - 行 159-200: テストケースループ（各テストケースの実行）
        - 行 201: イテレーション完了ログ出力
        - 行 202: JSON ファイルへのイテレーション結果保存
    - 12.1.2 **テストケースループ開始** - 行 159 で各テストケース（test_id, test_class）のループ開始
      - **ループ範囲**: 行 159 `for test_id, test_class in test_cases.items():` から 行 200 `log_test_result(test_id, result)` まで（例外処理含む）
      - **ループ変数**: test_id（テスト ID 文字列）, test_class（テストクラス）
      - **ループ内処理概要**:
        - 行 161-163: テスト有効性チェック（is_test_enabled）
        - 行 165-200: try-except ブロックでテスト実行とエラーハンドリング
        - 各テストケースごとに 12.1.3 から 12.1.9 の処理を実行
    - 12.1.3 **テストインスタンス生成** - 行 168 で test_instance = test_class()によりテストインスタンス生成
    - 12.1.4 **テスト実行開始** - 行 171 で result = test_instance.run()によりテスト実行開始
    - 12.1.5 **【ランダムパスワード抽出実行ポイント】** - テスト実行中に BaseTest.get_password()が呼び出される
      - 12.1.5.1 **A 用パスワード抽出** - test_cc_001_basic_creation.py 行 49 で password_a = self.get_password('A')実行
        - BaseTest.**init**() → \_initialize_random_passwords() → get_two_random_passwords()
        - test_passwords.txt から 24 個のパスワードの中から random.sample()で重複なし 2 個選択
        - 選択された A 用パスワードを self.results["password_a_random"]に保存
        - 選択された B 用パスワードを self.results["password_b_random"]に保存
        - BaseTest.get_password('A') → get_random_password('A') → self.results["password_a_random"]を返却
        - DEBUG ログ出力: "パーティション A のランダムパスワードを取得しました（長さ: {len(password)}）"
      - 12.1.5.2 **B 用パスワード抽出** - test_cc_001_basic_creation.py 行 52 で password_b = self.get_password('B')実行
        - BaseTest.get_password('B') → get_random_password('B') → self.results["password_b_random"]を返却
        - DEBUG ログ出力: "パーティション B のランダムパスワードを取得しました（長さ: {len(password)}）"
        - **重複排除保証**: random.sample()により A 用と B 用パスワードは必ず異なる値
      - 12.1.5.3 **CLI パスワード設定** - CLI 実行後にレスポンスから取得したパスワードを設定
        - BaseTest.set_cli_password('A', cli_response_password_a) → self.results["password_a_cli"]に保存
        - BaseTest.set_cli_password('B', cli_response_password_b) → self.results["password_b_cli"]に保存
        - DEBUG ログ出力: "パーティション A の CLI パスワードを設定しました（長さ: {len(password)}）"
    - 12.1.6 **CLI コマンド実行** - 抽出されたパスワードを使用して CLI コマンド実行
    - 12.1.7 **CLI レスポンス受信記録** - 行 174-176 で CLI レスポンス受信をファイルに記録
    - 12.1.8 **パスワード読み込み記録** - 行 178-183 でパスワード読み込みをファイルに記録
      - 12.1.8.1 **ランダムパスワード記録** - result["password_a_random"]が存在する場合、ログ出力とファイル記録
        - DEBUG ログ出力: "DEBUG: テスト {test_id} の A 用ランダムパスワード: {result['password_a_random']}"
        - DEBUG ログ出力: "DEBUG: テスト {test_id} の B 用ランダムパスワード: {result['password_b_random']}"
      - 12.1.8.2 **CLI パスワード記録** - result["password_a_cli"]が存在する場合、ログ出力とファイル記録
        - DEBUG ログ出力: "DEBUG: テスト {test_id} の A 用 CLI パスワード: {result['password_a_cli']}"
        - DEBUG ログ出力: "DEBUG: テスト {test_id} の B 用 CLI パスワード: {result['password_b_cli']}"
      - 12.1.8.3 **パスワード読み込み時刻記録** - パスワードが記録された場合のみ self.file_manager.update_password_loaded()実行
    - 12.1.9 **テスト結果記録** - 行 194 で test_results[test_id] = result によりテスト結果を記録（✅ 修正済み）
      - **修正前の問題**: TestResult 初期化時に古いパスワードフィールド名（password_a, password_b）を使用してエラー発生
      - **修正内容**: test_runner_V2_file_manager.py で新しいパスワードフィールド名（password_a_random, password_b_random, password_a_cli, password_b_cli）に変更
      - **修正結果**: テスト結果記録が正常に完了し、以降の処理が実行可能
    - 12.1.10 **イテレーション完了記録** - 行 202 で self.file_manager.add_iteration_result()により JSON ファイルに保存（✅ 正常実行）
      - **実行確認**: 5 回イテレーション全てが正常に完了し、JSON ファイルに保存
      - **ログ出力**: "テスト実行 #{iteration}/5 完了: 実行されたテスト数: 1"
    - 12.2 **テスト実行完了ログ** - "テスト実行が完了し、結果を JSON ファイルに保存しました"ログ出力（行 115）（✅ 正常実行）
13. **分析実行（JSON ファイル専用）** - analysis_executor.run_analysis_from_json_file(analyzers)実行（行 118）（✅ 正常実行）
    - 13.0 **JSON ファイルからデータ読み込み** - file_manager.get_execution_data()で JSON ファイルから実行データを取得
    - 13.0.1 **CLI パスワードを使用した復号処理** - \_perform_decryption_with_cli_passwords()で復号処理を実行
      - 13.0.1.1 **復号対象確認** - 最新イテレーションのテスト結果から CLI パスワードと暗号化ファイルの存在確認
      - 13.0.1.2 **復号実行** - \_decrypt_storage_file()で各テストの暗号化ファイルを復号
        - ログ出力: "テスト {test_id}: CLI パスワードを使用して復号を実行します"
        - ログ出力: " 暗号化ファイル: {test_result.storage_filepath}"
        - ログ出力: " A 用 CLI パスワード: {test_result.password_a_cli[:8]}..."
        - ログ出力: " B 用 CLI パスワード: {test_result.password_b_cli[:8]}..."
        - 実際の復号処理: 現在はログ出力のみ（復号ロジックは今後追加予定）
    - 13.1 **分析用データ構築** - JSON データから分析用データを構築（行 218-267）
      - 13.1.1 **最新イテレーション結果構築** - latest_test_results 辞書の構築（行 223-242）
        - **ループ範囲**: 行 224 `for test_id, test_result in latest_iteration.test_results.items():` から 行 242 まで
        - **ループ変数**: test_id（テスト ID 文字列）, test_result（TestResult オブジェクト）
        - **ループ処理**: 各テスト結果を分析用辞書形式に変換
      - 13.1.2 **全イテレーション結果構築** - all_test_results 配列の構築（行 245-267）
        - **外側ループ範囲**: 行 245 `for iteration_result in execution_data.test_execution["iterations"]:` から 行 267 まで
        - **外側ループ変数**: iteration_result（IterationResult オブジェクト）
        - **内側ループ範囲**: 行 247 `for test_id, test_result in iteration_result.test_results.items():` から 行 265 まで
        - **内側ループ変数**: test_id（テスト ID 文字列）, test_result（TestResult オブジェクト）
        - **ループ処理**: 各イテレーションの各テスト結果を分析用辞書形式に変換
    - 13.2 **分析実行メインループ** - 検出された分析モジュールごとの実行（行 275-318）
      - **ループ範囲**: 行 275 `for analyzer_id, analyzer_class in analyzers.items():` から 行 318 まで
      - **ループ変数**: analyzer_id（分析 ID 文字列）, analyzer_class（分析クラス）
      - **ループ継続・終了判断ポイント**:
        - **継続判断**: `analyzer_id in analyzers` の条件でループ継続（Python の dict.items() による自動制御）
        - **正常終了**: 全分析モジュールの実行完了後、自動的にループ終了
        - **スキップ条件**: is_analysis_enabled(analyzer_id) が False の場合、continue でスキップ（行 277-279）
        - **例外処理**: 個別分析の例外は catch されるが、**分析全体を停止する仕組みは未実装**
      - **ループ内処理概要**:
        - 行 276: 分析有効性チェック（設定による無効化確認）
        - 行 281: analyzer_instance = analyzer_class() で分析インスタンス生成
        - 行 284: 分析実行開始ログ出力
        - 行 286-295: map_intersection 分析の特別処理分岐
        - 行 296-305: その他分析の通常処理分岐
        - 行 306-318: 例外処理とエラー結果記録
    - 13.3 **map_intersection 分析の特別処理** - マップ交差分析の詳細ループ（行 286-295）
      - 13.3.1 **分析実行** - self.map_analyzer.analyze_with_file_tracking()実行（行 287-290）
      - 13.3.2 **比較結果記録の多重ループ（効率化版）** - \_record_comparison_results()内の 3 重ループ（行 156-177）
        - **A 用マップ比較ループ（効率化版）**:
          - **ループ範囲**: 行 158 `for comparison_key, rate in result["a_map_intersection"].items():` から 行 162 まで
          - **ループ変数**: comparison_key（比較キータプル）, rate（一致率数値）
          - **効率化実装**: map_intersection_analyzer.py で `i < j` 条件による重複計算排除
          - **計算量削減**: 10 回イテレーション時 90 回 → 45 回（50%削減）
          - **レポート要件維持**: 両方向キー `(i,j)` と `(j,i)` に同じ値を設定
          - **ループ処理**: A 用パーティションマップ間の比較結果を JSON ファイルに記録
          - **記録タイミング**: 各比較ペアごとに self.file_manager.add_map_comparison("a_map", comparison_str, rate) 実行
        - **B 用マップ比較ループ（効率化版）**:
          - **ループ範囲**: 行 165 `for comparison_key, rate in result["b_map_intersection"].items():` から 行 169 まで
          - **ループ変数**: comparison_key（比較キータプル）, rate（一致率数値）
          - **効率化実装**: map_intersection_analyzer.py で `i < j` 条件による重複計算排除
          - **計算量削減**: 10 回イテレーション時 90 回 → 45 回（50%削減）
          - **レポート要件維持**: 両方向キー `(i,j)` と `(j,i)` に同じ値を設定
          - **ループ処理**: B 用パーティションマップ間の比較結果を JSON ファイルに記録
          - **記録タイミング**: 各比較ペアごとに self.file_manager.add_map_comparison("b_map", comparison_str, rate) 実行
        - **A-B 間マップ比較ループ（効率化対象外）**:
          - **ループ範囲**: 行 172 `for comparison_key, rate in result["a_b_map_intersection"].items():` から 行 176 まで
          - **ループ変数**: comparison_key（比較キータプル）, rate（一致率数値）
          - **効率化対象外理由**: A-B 間比較は非対称のため効率化不可
          - **計算量**: 10 回イテレーション時 100 回（変更なし）
          - **ループ処理**: A 用と B 用パーティションマップ間の比較結果を JSON ファイルに記録
          - **記録タイミング**: 各比較ペアごとに self.file_manager.add_map_comparison("ab_map", comparison_str, rate) 実行
        - **効率化効果ログ出力**:
          - **計算回数比較**: "A 用マップ比較: {optimized}回実行 (効率化前: {original}回)"
          - **削減率表示**: "合計計算回数: {total_optimized}回 (効率化前: {total_original}回, {reduction_rate:.1f}%削減)"
          - **10 回イテレーション例**: 280 回 → 190 回（32%削減）
      - 13.3.3 **最終結果記録** - self.file_manager.complete_map_intersection_analysis(result)で最終結果を JSON ファイルに記録（行 179）
    - 13.4 **その他分析の通常処理** - map_intersection 以外の分析実行（行 296-305）
      - 13.4.1 **分析実行** - analyzer_instance.analyze(latest_test_results)実行（行 297）
      - 13.4.2 **結果判定とログ出力** - result.get("pass", False)で合否判定（行 298-301）
      - 13.4.3 **結果記録** - self.file_manager.add_other_analysis_result(analyzer_id, result)で JSON ファイルに記録（行 304）
    - 13.5 **分析実行完了ログ** - "JSON ファイルベースの分析処理が完了しました"ログ出力（行 320）（✅ 正常実行）
      - **実行確認**: map_intersection 分析と key_length 分析が実行完了
      - **効率化効果**: A 用・B 用マップ比較で 30.8%の計算量削減を達成
      - **✅ JSON シリアライゼーション警告解決**: タプルキーを文字列キーに変換し、警告が完全に消失
14. **レポート生成（JSON ファイル専用）** - \_generate_and_save_report_from_json()実行（行 122）（⚠️ 部分実行）
    - 14.0 **JSON ファイルからデータ読み込み** - file_manager.get_current_file_path()で JSON ファイルパスを取得（✅ 正常実行）
    - 14.0.1 **新パスワード形式対応** - レポートテンプレートで新しいパスワード形式に対応（✅ 正常実行）
      - テンプレート形式: "パスワード: {A 用パスワードランダム結果}:{A 用パスワード CLI からの返却結果}"
      - プレースホルダー処理: get_placeholder_value()で"用パスワードランダム結果"と"用パスワード CLI からの返却結果"を個別処理
      - データ取得: password_a_random, password_b_random, password_a_cli, password_b_cli フィールドから取得
      - CLI レスポンス正確性確認: ランダムパスワードと CLI レスポンスパスワードの比較が可能
    - 14.1 **レポート生成メソッド呼び出し** - self.\_generate_and_save_report_from_json()で戻り値なしのレポート生成（行 122）（❌ エラー発生）
      - **✅ JSON ファイル読み込み成功**: JSON ファイルからデータの正常読み込みを確認
      - **✅ レポート生成開始**: テンプレート処理とプレースホルダー置換が開始
      - **❌ NoneType エラー**: utils/report_generator.py 185 行目で `stdout.replace('\n', ' ')` 実行時に stdout が None でエラー発生
      - **影響**: レポート生成は失敗したが、テスト実行とデータ保存は正常完了
15. **テスト完了ログ** - "テスト実行が完了しました"メッセージ出力（行 125）（✅ 正常実行）
16. **結果集計（JSON ファイル専用）** - \_count_results_from_json()で成功数と失敗数をカウント（行 128）（✅ 正常実行）
    - 16.1 **JSON ファイルからデータ取得** - file_manager.get_execution_data()で JSON ファイルから実行データを取得（✅ 正常実行）
    - 16.2 **結果カウントメソッド呼び出し** - success_count, failure_count = self.\_count_results_from_json()でタプル取得（行 128）（✅ 正常実行）
17. **結果サマリーログ** - 合計/成功/失敗数を出力（行 130）（✅ 正常実行）
    - 17.1 **結果サマリー計算** - success_count + failure_count で合計数計算（✅ 正常実行）
    - 17.2 **結果サマリーログ出力** - "テスト結果: 合計=1, 成功=1, 失敗=0"ログ出力（行 130）（✅ 正常実行）
18. **終了コード決定** - テスト成功/失敗で 0/1 を返却（行 133）（✅ 正常実行）
    - 18.1 **終了コード判定** - return 0 if failure_count == 0 else 1 で失敗数ゼロなら 0、それ以外は 1 を返却（行 133）（✅ 正常実行）
    - **実行結果**: 全テスト成功のため終了コード 0 を返却
19. **プロセス終了** - sys.exit()で main()の戻り値を終了コードに設定（行 346）（✅ 正常実行）
    - 19.1 **メイン例外時の終了コード 1 返却** - run()メソッドで Exception 発生時は log_error()と try-except 内で file_manager.mark_error()実行後、終了コード 1 を返却（行 135-144）（✅ 正常実行）
    - 19.2 **main()関数実行** - runner = TestRunnerV2()でインスタンス生成、return runner.run()で実行（行 342-343）（✅ 正常実行）
    - 19.3 **プロセス終了実行** - sys.exit(main())で main()の戻り値を終了コードに設定（行 346）（✅ 正常実行）
    - **最終結果**: 終了コード 0 でプロセス正常終了

## 1.1 ランダムパスワード抽出ポイント

### 1.1.1 パスワードファイル構成（test_passwords.txt）

**パスワード総数**: 24 個
**パスワード種別**:

- 基本パスワード: password, Password123, weak, 12345678, abcdefgh, ABCDEFGH
- 特殊文字含有: p@ssw0rd!, strongP@ssword123, P@$$w0rd_W1th-Sp3c!@l_Ch@r@ct3r$
- 長文パスワード: ThisIsAVeryLongPasswordThatExceedsTwentyCharacters
- スペース含有: "pass word with spaces", "EmptySpaceAtEnd", " EmptySpaceAtStart"
- 日本語パスワード: パスワード 123, パスワード！＠＃＄％, password\_四\_user_bBBB
- 絵文字含有: test*password*😄
- 用途別パスワード: PW_4_user_a, UserA_P@ssw0rd, UserB_P@ssw0rd, Partition_A_Key123!, Partition_B_Key456!
- テスト用パスワード: test_password_aaaa, shamir_secret_test

### 1.1.2 ランダム抽出実装ポイント

**実装場所**: utils/password_manager.py
**主要関数**:

- `get_random_password()` - 24 個のパスワードから random.choice()でランダム選択
- `get_password_for_partition(partition)` - パーティション別パスワード取得（内部で get_random_password()を呼び出し）

**抽出タイミング**:

1. **BaseTest.get_password()呼び出し時** - 各テストケースでパーティション用パスワード要求時

   - BaseTest.get_password('A') → utils.password_manager.get_password_for_partition('A') → get_random_password()
   - BaseTest.get_password('B') → utils.password_manager.get_password_for_partition('B') → get_random_password()

2. **テスト実行中の記録ポイント**:

   - **行 175-180**: TestExecutor.run_tests()内でパスワード読み込み検出時
   - 行 177\*\*: `self.logger.info(f"DEBUG: テスト {test_id} のA用パスワード: {result['password_a']}")`
   - 行 179\*\*: `self.logger.info(f"DEBUG: テスト {test_id} のB用パスワード: {result['password_b']}")`
   - 行 181\*\*: `self.file_manager.update_password_loaded(test_id, iteration + 1)`

3. **JSON ファイル記録ポイント**:
   - **TestResult.password_a**: A 用パスワードの平文記録
   - **TestResult.password_b**: B 用パスワードの平文記録
   - **TestResult.password_loaded**: パスワード読み込み時刻記録

### 1.1.3 ランダム性の特徴

**選択アルゴリズム**: Python 標準ライブラリの random.choice()
**重複許可**: 同一テスト実行内で同じパスワードが複数回選択される可能性あり
**決定論性**: シード固定なし（実行ごとに異なる選択結果）
**分布**: 24 個のパスワードに対して均等分布（理論上）

**実際の選択例**:

- テスト実行 1 回目: A 用="password", B 用="strongP@ssword123"
- テスト実行 2 回目: A 用="パスワード 123", B 用="password"（重複可能）
- テスト実行 3 回目: A 用="test*password*😄", B 用="Partition_A_Key123!"

### 1.1.4 セキュリティ考慮事項

**平文記録**: JSON ファイルとログにパスワード平文を記録（デバッグ目的）
**ハッシュ化機能**: password_manager.get_password_hash()で SHA-256 ハッシュ化可能
**ファイルアクセス制御**: test_passwords.txt の読み込み権限に依存
**ログ出力制御**: DEBUG レベルでパスワード平文をログ出力

## 2 実装不足・問題点

### 2.1 ✅ レポート生成関数の引数不整合（修正済み）

- **修正済み**: generate_report_from_json_file()を新規実装し、JSON ファイルからデータを読み込んでレポート生成

### 2.2 ✅ JSON ファイルを唯一のデータ源泉とする適正化（実装済み）

- **実装済み**:
  - **メモリ上データ排除**: test_executor.run_tests()はメモリ上のデータを返さず、JSON ファイルのみに保存
  - **JSON ファイル専用分析**: analysis_executor.run_analysis_from_json_file()で JSON ファイルからデータを読み込んで分析実行
  - **JSON ファイル専用レポート**: generate_report_from_json_file()で JSON ファイルからレポート生成
  - **データ整合性確保**: 常に JSON ファイルを唯一のデータ源泉として使用
- **設計の妥当性**: JSON ファイルを唯一のデータ源泉とすることで、データの不整合を防止し、デバッグ性と信頼性を向上

### 2.3 ✅ パスワード管理の改善（実装済み）

- **実装済み**:
  - **重複なしパスワード抽出**: get_two_random_passwords()で random.sample()を使用し、A 用と B 用パスワードの重複を完全排除
  - **パスワード分離管理**: ランダムパスワード（password_a_random, password_b_random）と CLI パスワード（password_a_cli, password_b_cli）を分離保存
  - **CLI パスワード復号対応**: 分析実行前に CLI パスワードを使用した復号処理を実装（\_perform_decryption_with_cli_passwords()）
  - **レポート形式改善**: "パスワード: {ランダム結果}:{CLI 返却結果}"形式で CLI レスポンスの正確性確認が可能
  - **データ構造拡張**: TestResult クラスに新しいパスワードフィールドを追加し、JSON 保存・読み込みに対応
  - **旧パスワードフィールド削除**: password_a, password_b フィールドを完全削除し、新しいパスワード管理システムのみに統一

### 2.4 ✅ エラーハンドリングの不完全性（部分修正済み）

- **部分修正済み**: try-except 内でのエラーハンドリングを強化、レポート生成失敗時の継続処理を実装
- **残課題**: 部分的成功時のレポート生成機能は未実装

### 2.5 ✅ 旧テストランナー考慮動作の完全削除（実装済み）

- **実装済み**:
  - **旧パスワードフィールド削除**: password_a, password_b フィールドを全コンポーネントから完全削除
  - **旧メソッド削除**: \_generate_and_save_report()メソッドを完全削除
  - **互換性処理削除**: 旧テストランナーとの互換性維持処理を全て削除
  - **レポート生成最適化**: 新しいパスワード管理システムのみに対応したレポート生成に統一
  - **データ変換最適化**: 不要な旧形式データ変換処理を削除し、処理速度を向上

### 2.6 ✅ フォールバック処理の明示化（実装済み）

- **実装済み**: 各種フォールバック処理を明示的に実装
  - 設定ファイル読み込み失敗時の即座終了
  - テストケース未発見時の即座終了
  - 分析モジュール未発見時の継続処理
  - JSON ファイルからのデータ取得失敗時のフォールバック処理
  - レポート生成失敗時の継続処理

### 2.7 🔄 復号ロジックの実装（今後追加予定）

- **現状**: CLI パスワードを使用した復号処理のフレームワークは実装済み
- **今後追加予定**: \_decrypt_storage_file()内の実際の復号ロジック実装
- **影響**: 現在は復号処理のログ出力のみで、実際の復号は未実行

### 2.8 ✅ TestResult 初期化エラーの修正（修正済み）

- **問題**: test_runner_V2_file_manager.py の 138-139 行で古いパスワードフィールド名（password_a, password_b）を使用
- **修正内容**:
  - **password_a** → **password_a_random**
  - **password_b** → **password_b_random**
  - **password_a_cli**, **password_b_cli** フィールドを追加
- **修正結果**: **12.1.9 テスト結果記録**が正常に完了し、**13-19**の全処理が実行完了
- **実行確認**: 5 回イテレーション × 1 テストケースが正常実行、終了コード 0 で完了

### 2.9 ⚠️ JSON シリアライゼーション警告（新規発見）

- **問題**: `keys must be str, int, float, bool or None, not tuple`
- **発生箇所**:
  - マップ交差分析完了時のファイル書き込み
  - 分析完了時のファイル書き込み
  - レポート生成開始/完了時のファイル書き込み
- **影響**: 警告レベルのため処理は継続されるが、JSON ファイルの一部データが正しく保存されない可能性
- **推奨改善**: タプルキーを文字列キーに変換する処理の追加

### 2.10 ❌ レポート生成時の JSON 解析エラー（新規発見）

- **問題**: `Expecting property name enclosed in double quotes: line 60537 column 11`
- **発生箇所**: **14. レポート生成（JSON ファイル専用）**での JSON ファイル読み込み時
- **原因**: JSON シリアライゼーション警告と関連し、不正な JSON 形式でファイルが保存されている可能性
- **影響**: レポート生成が失敗するが、テスト実行とデータ保存は正常完了
- **推奨改善**: JSON シリアライゼーション問題の解決後に自動的に修正される見込み

### 2.11 ✅ JSON シリアライゼーション警告の完全解決（修正済み）

- **問題**: `keys must be str, int, float, bool or None, not tuple`
- **修正内容**:
  - **map_intersection_analyzer.py**: タプルキー `(i,j)` を文字列キー `"i-j"` に変換
  - **test_runner_V2_analysis_executor.py**: 文字列キーをそのまま使用するように修正
- **修正結果**: **13.3.2 比較結果記録の多重ループ**で JSON シリアライゼーション警告が完全に消失
- **実行確認**: 5 回イテレーション × 1 テストケースが正常実行、JSON ファイルの正常保存を確認
- **効率化効果**: A 用・B 用マップ比較で 30.8%の計算量削減を維持

### 2.12 ⚠️ レポート生成時の NoneType エラー（新規発見）

- **問題**: `'NoneType' object has no attribute 'replace'`
- **発生箇所**: **14.1 レポート生成メソッド呼び出し**での utils/report_generator.py 185 行目
- **原因**: `get_partition_map_key_from_stdout(stdout, partition)` で stdout 値が None の場合にエラー発生
- **影響**: レポート生成は失敗するが、テスト実行とデータ保存は正常完了
- **推奨改善**: stdout 値の Null チェック処理の追加

### 2.13 ✅ ログパス最適化の完全実装（修正済み）

- **問題**: ログが間違った場所 `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_13_shamir_multi_plaintext_system/method_13_shamir_multi_plaintext_system/test/logs` に出力されていた
- **修正内容**:
  - **utils/test_logger.py**: `get_log_dir()` 関数で test_runner_V2.py の絶対パスを基準にログディレクトリを決定
  - **パス計算最適化**: 複雑なパス計算を削除し、`__file__` を基準とした相対パス計算に変更
  - **正確なパス決定**: `test_dir = os.path.dirname(utils_dir)` で test/ ディレクトリを正確に特定
- **修正結果**: **2.1 ログディレクトリパス決定**で正しいパス `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_13_shamir_multi_plaintext_system/test/logs/` に出力
- **実行確認**: ログファイルが正しい場所に生成され、"ロガーを設定しました" メッセージで確認完了
- **パス一貫性**: 1.1 で取得した test_runner_V2.py の絶対パスと一貫したディレクトリ構造を維持

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
            "password_a_random": "ランダムに選択されたA用パスワード",
            "password_b_random": "ランダムに選択されたB用パスワード",
            "password_a_cli": "CLIレスポンスから取得したA用パスワード",
            "password_b_cli": "CLIレスポンスから取得したB用パスワード",
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

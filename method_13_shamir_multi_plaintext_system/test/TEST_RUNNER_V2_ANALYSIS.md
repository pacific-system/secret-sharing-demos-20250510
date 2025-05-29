# テストランナー V2 現状分析ドキュメント

## 1 メイン処理シーケンス

1. **実行環境確定** - プロセス冒頭で test_runner_V2.py の絶対パス取得（行 32-37）
   - 1.1 **test_runner_V2.py 絶対パス取得** - os.path.abspath(**file**)で TEST_RUNNER_V2_FILE_PATH 取得（行 32）
   - 1.2 **実行ディレクトリ導出** - os.path.dirname()で TEST_RUNNER_V2_DIR 取得（行 33）
   - 1.3 **カレントディレクトリ変更** - os.chdir(TEST_RUNNER_V2_DIR)で実行環境を確定（行 36）
2. **ログ設定初期化** - setup_logger()でログ環境構築（行 47、実行環境確定後）
   - 2.1 **ログディレクトリ作成** - logs/ディレクトリの自動作成（確定された実行環境下）
   - 2.2 **ログファイル生成** - test*log*{timestamp}.log ファイル作成
   - 2.3 **ハンドラー設定** - コンソール出力とファイル出力の両方設定
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
    - 12.1.2 **テストケースループ開始** - 行 160 で各テストケース（test_id, test_class）のループ開始
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
      - 12.1.8.3 **互換性パスワード記録** - result["password_a"]が存在する場合、ログ出力とファイル記録（互換性のため）
      - 12.1.8.4 **パスワード読み込み時刻記録** - パスワードが記録された場合のみ self.file_manager.update_password_loaded()実行
    - 12.1.9 **テスト結果記録** - 行 194 で test_results[test_id] = result によりテスト結果を記録
    - 12.1.10 **イテレーション完了記録** - 行 202 で self.file_manager.add_iteration_result()により JSON ファイルに保存
    - 12.2 **テスト実行完了ログ** - "テスト実行が完了し、結果を JSON ファイルに保存しました"ログ出力（行 115）
13. **分析実行（JSON ファイル専用）** - analysis_executor.run_analysis_from_json_file(analyzers)実行（行 118）
    - 13.0 **JSON ファイルからデータ読み込み** - file_manager.get_execution_data()で JSON ファイルから実行データを取得
    - 13.0.1 **CLI パスワードを使用した復号処理** - \_perform_decryption_with_cli_passwords()で復号処理を実行
      - 13.0.1.1 **復号対象確認** - 最新イテレーションのテスト結果から CLI パスワードと暗号化ファイルの存在確認
      - 13.0.1.2 **復号実行** - \_decrypt_storage_file()で各テストの暗号化ファイルを復号
        - ログ出力: "テスト {test_id}: CLI パスワードを使用して復号を実行します"
        - ログ出力: " 暗号化ファイル: {test_result.storage_filepath}"
        - ログ出力: " A 用 CLI パスワード: {test_result.password_a_cli[:8]}..."
        - ログ出力: " B 用 CLI パスワード: {test_result.password_b_cli[:8]}..."
        - 実際の復号処理: 現在はログ出力のみ（復号ロジックは今後追加予定）
    - 13.1 **分析実行メソッド呼び出し** - self.analysis_executor.run_analysis_from_json_file(analyzers)で戻り値なしの分析実行（行 118）
    - 13.2 **分析実行完了ログ** - "分析実行が完了し、結果を JSON ファイルに保存しました"ログ出力（行 119）
14. **レポート生成（JSON ファイル専用）** - \_generate_and_save_report_from_json()実行（行 122）
    - 14.0 **JSON ファイルからデータ読み込み** - file_manager.get_current_file_path()で JSON ファイルパスを取得
    - 14.0.1 **新パスワード形式対応** - レポートテンプレートで新しいパスワード形式に対応
      - テンプレート形式: "パスワード: {A 用パスワードランダム結果}:{A 用パスワード CLI からの返却結果}"
      - プレースホルダー処理: get_placeholder_value()で"用パスワードランダム結果"と"用パスワード CLI からの返却結果"を個別処理
      - データ取得: password_a_random, password_b_random, password_a_cli, password_b_cli フィールドから取得
      - CLI レスポンス正確性確認: ランダムパスワードと CLI レスポンスパスワードの比較が可能
    - 14.1 **レポート生成メソッド呼び出し** - self.\_generate_and_save_report_from_json()で戻り値なしのレポート生成（行 122）
15. **テスト完了ログ** - "テスト実行が完了しました"メッセージ出力（行 125）
16. **結果集計（JSON ファイル専用）** - \_count_results_from_json()で成功数と失敗数をカウント（行 128）
    - 16.1 **JSON ファイルからデータ取得** - file_manager.get_execution_data()で JSON ファイルから実行データを取得
    - 16.2 **結果カウントメソッド呼び出し** - success_count, failure_count = self.\_count_results_from_json()でタプル取得（行 128）
17. **結果サマリーログ** - 合計/成功/失敗数を出力（行 130）
    - 17.1 **結果サマリー計算** - success_count + failure_count で合計数計算
    - 17.2 **結果サマリーログ出力** - "テスト結果: 合計={success_count + failure_count}, 成功={success_count}, 失敗={failure_count}"ログ出力（行 130）
18. **終了コード決定** - テスト成功/失敗で 0/1 を返却（行 133）
    - 18.1 **終了コード判定** - return 0 if failure_count == 0 else 1 で失敗数ゼロなら 0、それ以外は 1 を返却（行 133）
19. **プロセス終了** - sys.exit()で main()の戻り値を終了コードに設定（行 346）
    - 19.1 **メイン例外時の終了コード 1 返却** - run()メソッドで Exception 発生時は log_error()と try-except 内で file_manager.mark_error()実行後、終了コード 1 を返却（行 135-144）
    - 19.2 **main()関数実行** - runner = TestRunnerV2()でインスタンス生成、return runner.run()で実行（行 342-343）
    - 19.3 **プロセス終了実行** - sys.exit(main())で main()の戻り値を終了コードに設定（行 346）

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
   - **行 177**: `self.logger.info(f"DEBUG: テスト {test_id} のA用パスワード: {result['password_a']}")`
   - **行 179**: `self.logger.info(f"DEBUG: テスト {test_id} のB用パスワード: {result['password_b']}")`
   - **行 181**: `self.file_manager.update_password_loaded(test_id, iteration + 1)`

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

### 2.3 ✅ パスワード管理の改善（実装済み）

- **実装済み**:
  - **重複なしパスワード抽出**: get_two_random_passwords()で random.sample()を使用し、A 用と B 用パスワードの重複を完全排除
  - **パスワード分離管理**: ランダムパスワード（password_a_random, password_b_random）と CLI パスワード（password_a_cli, password_b_cli）を分離保存
  - **CLI パスワード復号対応**: 分析実行前に CLI パスワードを使用した復号処理を実装（\_perform_decryption_with_cli_passwords()）
  - **レポート形式改善**: "パスワード: {ランダム結果}:{CLI 返却結果}"形式で CLI レスポンスの正確性確認が可能
  - **データ構造拡張**: TestResult クラスに新しいパスワードフィールドを追加し、JSON 保存・読み込みに対応

### 2.4 ✅ エラーハンドリングの不完全性（部分修正済み）

- ~~問題: 各コンポーネント間の連携でエラーが発生した場合の処理が不十分~~
- ~~実態: file_manager.mark_error()は呼ばれるが、部分的な成功データの活用方法が未定義~~
- ~~影響: 途中でエラーが発生した場合、それまでの結果が無駄になる~~
- **部分修正済み**: try-except 内でのエラーハンドリングを強化、レポート生成失敗時の継続処理を実装
- **残課題**: 部分的成功時のレポート生成機能は未実装

### 2.5 ✅ 互換性維持の複雑性（適正化済み）

- ~~問題: 既存の all_test_results 形式との互換性維持のため、データ変換処理が複雑~~
- ~~実態: TestExecutor で互換性用のデータ変換を行っているが、パフォーマンス影響あり~~
- ~~影響: メモリ使用量増加、処理速度低下~~
- **適正化済み**:
  - **JSON ファイル構造に統一**: 全処理を JSON ファイル構造に合わせて適正化
  - **メモリ使用量削減**: メモリ上のデータ保持を排除し、メモリ使用量を大幅削減
  - **処理速度向上**: 不要なデータ変換処理を削除し、処理速度を向上
  - **データ変換の最適化**: generate_report_from_json_file()内でのみ必要最小限のデータ変換を実行

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

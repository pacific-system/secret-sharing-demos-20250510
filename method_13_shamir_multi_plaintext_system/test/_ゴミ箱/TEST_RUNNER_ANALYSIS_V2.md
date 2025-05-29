# テストランナー現状分析ドキュメント V2

## 1 メイン処理シーケンス

1. **ログ設定初期化** - setup_logger()でログ環境構築
   - 1.1 **ログディレクトリ作成** - logs/ディレクトリの自動作成
   - 1.2 **ログファイル生成** - test*log*{timestamp}.log ファイル作成
   - 1.3 **ハンドラー設定** - コンソール出力とファイル出力の両方設定
2. **テスト実行開始ログ** - "テスト実行を開始します"メッセージ出力
3. **設定ファイル読み込み** - load_config()実行、失敗時は即座終了
4. **テストケース検出** - discover_test_cases()実行、未発見時は即座終了
   - 4.1 **ディレクトリスキャン** - test_cases/配下の 3 ディレクトリを検索
   - 4.2 **ファイルパターンマッチ** - test\_\*.py ファイルを検索
   - 4.3 **動的モジュールインポート** - importlib.import_module()でロード
   - 4.4 **クラス検査** - BaseTest 継承クラスを検出
   - 4.5 **インスタンス化と ID 検証** - test_id 属性の有効性確認
   - 4.6 **検出結果の一時保存** - test_cases 辞書にテストクラスを保存
5. **分析モジュール検出** - discover_analyzers()実行、未発見でも継続
   - 5.1 **分析ディレクトリスキャン** - analysis/ディレクトリを検索
   - 5.2 **アナライザーファイル検索** - \*\_analyzer.py パターンマッチ
   - 5.3 **アナライザークラス検出** - \*Analyzer で終わるクラス名を検索
   - 5.4 **name 属性検証** - 有効な name 属性を持つかチェック
   - 5.5 **検出結果の一時保存** - analyzers 辞書にアナライザークラスを保存
6. **テスト実行** - run_tests()実行、繰り返し実行対応
   - 6.1 **繰り返し回数設定** - 設定ファイルから読み込み（1-10 回制限）（行 158-167）
   - 6.2 **<span style="color: green;">累積保存用データ構造準備</span>** - <span style="color: green;">all_test_results=[]</span>で全イテレーション結果の累積保存準備（1 回のみ実行）（行 171）
   - 6.3 **イテレーションループ開始** - 指定回数分の繰り返し実行（行 173）
   - 6.4 **イテレーション用データ構造初期化** - test_results={}で各イテレーション用辞書作成（ループ内で毎回実行）（行 175）
   - 6.5 **テストケース有効性チェック** - is_test_enabled()で確認（行 178-180）
   - 6.6 **テストインスタンス生成** - 各テストクラスのインスタンス化（行 184）
   - 6.7 **個別テスト実行** - test_instance.run()呼び出し（行 187-188）
   - 6.8 **パスワード処理** - test_passwords.txt から読み込み（個別テスト内）
   - 6.9 **CLI 引数ログ出力** - テスト結果の CLI 引数を記録（行 191-192）
   - 6.10 **パスワードデバッグログ** - A/B 用パスワードを DEBUG レベルで出力（行 194-197）
   - 6.11 **結果記録** - 成功/失敗とエラー情報を構造化記録（行 199-204）
   - 6.12 **テスト結果ログ保存** - log_test_result()でログファイルに永続化（行 207）
   - 6.13 **<span style="color: green;">イテレーション結果の確定保存</span>** - <span style="color: green;">iteration_results 辞書作成後、all_test_results.append()で test_id, success, cli_args, password_a, password_b, stdout, stderr, exit_code, storage_filename, partition_map_a, partition_map_b, execution_time, performance_data, error</span>を累積保存（ループ内で毎回実行）（行 212-216）
7. **分析実行** - run_analysis()実行、テスト結果を基に分析
   - 7.1 **分析処理開始ログ** - log_info("分析処理を実行しています...")出力（行 231）
   - 7.2 **分析結果辞書初期化** - analysis_results = {}で空辞書作成（行 232）
   - 7.3 **最新テスト結果初期化** - latest_test_results = {}で空辞書作成（行 235）
   - 7.4 **最新テスト結果取得条件** - if all_test_results:で条件判定（行 236）
   - 7.5 **最新テスト結果取得** - latest_test_results = all_test_results[-1]["results"]で取得（行 237）
   - 7.6 **アナライザーループ開始** - for analyzer_id, analyzer_class in analyzers.items():でループ開始（行 239）
   - 7.7 **分析有効性チェック** - if not is_analysis_enabled(analyzer_id):で確認（行 241）
   - 7.8 **無効時ログ出力** - log_info(f"分析 {analyzer_id} は設定で無効化されているためスキップします")出力（行 242）
   - 7.9 **無効時スキップ** - continue 実行（行 243）
   - 7.10 **try 文開始** - try:でエラーハンドリング開始（行 245）
   - 7.11 **分析インスタンス生成** - analyzer_instance = analyzer_class()でインスタンス化（行 247）
   - 7.12 **分析実行ログ** - log_info(f"分析 {analyzer_id} ({analyzer_class.**name**}) を実行しています...")出力（行 250）
   - 7.13 **特別処理判定** - if analyzer_id == "map_intersection" and all_test_results:で条件分岐（行 253）
   - 7.14 **map_intersection 特別処理** - result = analyzer_instance.analyze(latest_test_results, all_test_results)実行（行 254）
     - 7.14.1 **<span style="color: blue;">A 用パーティションマップキー総当たり評価開始</span>** - <span style="color: blue;">全イテレーション間での A 領域マップ総当たり比較処理開始</span>
       - 7.14.1.1 **<span style="color: blue;">基準マップデコード</span>** - <span style="color: blue;">iteration 1 の partition_map_a から 5000 近い配列要素をデコード取得</span>
       - 7.14.1.2 **<span style="color: blue;">比較対象マップデコード</span>** - <span style="color: blue;">iteration 2 の partition_map_a から 5000 近い配列要素をデコード取得</span>
       - 7.14.1.3 **<span style="color: blue;">A 用 INDEX 一致率評価実装</span>** - <span style="color: blue;">2 つの配列間での要素一致率計算処理実行</span>
       - 7.14.1.4 **<span style="color: blue;">A 用評価結果保存</span>** - <span style="color: blue;">計算結果を a_map_intersection 辞書に(1,2)キーで保存</span>
       - 7.14.1.5 **<span style="color: blue;">次回戦処理</span>** - <span style="color: blue;">iteration 1 vs 3, 1 vs 4, 1 vs 5...と順次総当たり実行</span>
       - 7.14.1.6 **<span style="color: blue;">全組み合わせ完了</span>** - <span style="color: blue;">全イテレーション間の総当たり比較完了まで繰り返し</span>
     - 7.14.2 **<span style="color: blue;">B 用パーティションマップキー総当たり評価開始</span>** - <span style="color: blue;">全イテレーション間での B 領域マップ総当たり比較処理開始</span>
       - 7.14.2.1 **<span style="color: blue;">基準マップデコード</span>** - <span style="color: blue;">iteration 1 の partition_map_b から 5000 近い配列要素をデコード取得</span>
       - 7.14.2.2 **<span style="color: blue;">比較対象マップデコード</span>** - <span style="color: blue;">iteration 2 の partition_map_b から 5000 近い配列要素をデコード取得</span>
       - 7.14.2.3 **<span style="color: blue;">B 用 INDEX 一致率評価実装</span>** - <span style="color: blue;">2 つの配列間での要素一致率計算処理実行</span>
       - 7.14.2.4 **<span style="color: blue;">B 用評価結果保存</span>** - <span style="color: blue;">計算結果を b_map_intersection 辞書に(1,2)キーで保存</span>
       - 7.14.2.5 **<span style="color: blue;">次回戦処理</span>** - <span style="color: blue;">iteration 1 vs 3, 1 vs 4, 1 vs 5...と順次総当たり実行</span>
       - 7.14.2.6 **<span style="color: blue;">全組み合わせ完了</span>** - <span style="color: blue;">全イテレーション間の総当たり比較完了まで繰り返し</span>
     - 7.14.3 **<span style="color: blue;">A-B 間パーティションマップキー総当たり評価開始</span>** - <span style="color: blue;">A 領域と B 領域間での総当たり比較処理開始</span>
       - 7.14.3.1 **<span style="color: blue;">A 領域マップデコード</span>** - <span style="color: blue;">iteration 1 の partition_map_a から 5000 近い配列要素をデコード取得</span>
       - 7.14.3.2 **<span style="color: blue;">B 領域マップデコード</span>** - <span style="color: blue;">iteration 1 の partition_map_b から 5000 近い配列要素をデコード取得</span>
       - 7.14.3.3 **<span style="color: blue;">A-B 間 INDEX 一致率評価実装</span>** - <span style="color: blue;">A 領域と B 領域配列間での要素一致率計算処理実行</span>
       - 7.14.3.4 **<span style="color: blue;">A-B 間評価結果保存</span>** - <span style="color: blue;">計算結果を a_b_map_intersection 辞書に(1,1)キーで保存</span>
       - 7.14.3.5 **<span style="color: blue;">次回戦処理</span>** - <span style="color: blue;">A1 vs B2, A1 vs B3, A2 vs B1...と順次総当たり実行</span>
       - 7.14.3.6 **<span style="color: blue;">全組み合わせ完了</span>** - <span style="color: blue;">全 A-B 間の総当たり比較完了まで繰り返し</span>
     - 7.14.4 **<span style="color: blue;">負荷重処理完了ログ</span>** - <span style="color: blue;">3 種類の総当たり評価（A 用、B 用、A-B 間）の負荷重処理完了をログ出力</span>
   - 7.15 **特別処理ログ** - log_info(f"パーティション MAP 交差分析に all_test_results を渡しました（テスト実行数: {len(all_test_results)}）")出力（行 255）
   - 7.16 **通常処理** - else:文で result = analyzer_instance.analyze(latest_test_results)実行（行 257）
   - 7.17 **分析結果判定** - success = result.get("pass", False)で成功判定（行 260）
   - 7.18 **ステータス文字列生成** - status = "合格" if success else "不合格"で文字列作成（行 261）
   - 7.19 **分析結果ログ出力** - log_info(f"分析 {analyzer_id} の実行結果: {status}")出力（行 262）
   - 7.20 **<span style="color: green;">分析結果の確定保存</span>** - <span style="color: green;">analysis_results[analyzer_id] = result</span>で分析結果を辞書に保存（行 264）
   - 7.21 **例外処理開始** - except Exception as e:で例外キャッチ（行 265）
   - 7.22 **例外ログ出力** - log_error(f"分析 {analyzer_id} の実行中にエラーが発生しました: {str(e)}")出力（行 266）
   - 7.23 **例外時結果保存** - analysis_results[analyzer_id]にエラー情報辞書を保存（行 267-271）
   - 7.24 **分析完了ログ** - log_info(f"実行された分析数: {len(analysis_results)}")出力（行 273）
   - 7.25 **分析結果返却** - return analysis_results 実行（行 274）
8. **レポート生成** - generate_report()実行、失敗でも継続
   - 8.1 **レポート生成開始ログ** - "テストレポートを生成しています..."出力
   - 8.2 **最新テスト結果取得** - all_test_results[-1]["results"]から動的取得
   - 8.3 **タイムスタンプ生成** - YYYYMMDD_HHMMSS 形式
   - 8.4 **ファイル名決定** - test*report*{timestamp}.md
   - 8.5 **<span style="color: green;">全結果データ統合</span>** - <span style="color: green;">最新結果, analysis_results, all_test_results</span>を統合してレポート生成
9. **レポート保存** - save_report()実行、失敗でも継続
   - 9.1 **保存成功時** - 保存完了ログ出力
   - 9.2 **保存失敗時** - エラーログ出力（処理継続）
   - 9.3 **<span style="color: green;">レポートファイル永続化</span>** - <span style="color: green;">test*report*{timestamp}.md</span>ファイル作成
10. **テスト完了ログ** - "テスト実行が完了しました"メッセージ出力
11. **結果集計** - 成功数と失敗数をカウント
    - 11.1 **最新結果から集計** - all_test_results[-1]["results"]から統計計算
12. **結果サマリーログ** - 合計/成功/失敗数を出力
13. **終了コード決定** - テスト成功/失敗で 0/1 を返却
14. **プロセス終了** - sys.exit()で main()の戻り値を終了コードに設定

## 2 データ構造

### 2.1 all_test_results 構造（実際の実装）

```
[
  {
    "iteration": 1,
    "results": {
      "test_id": {
        "test_id": "test_id",
        "success": true/false,
        "cli_args": {...},
        "password_a": "...",
        "password_b": "...",
        "stdout": "...",
        "stderr": "...",
        "exit_code": 0/-1,
        "storage_filename": "...",
        "partition_map_a": {...},
        "partition_map_b": {...},
        "execution_time": 0.0,
        "performance_data": {...},
        "error": "..."
      }
    }
  },
  ...
]
```

### 2.2 analysis_results 構造（実際の実装）

```
{
  "map_intersection": {
    "name": "map_intersection",
    "pass": true/false,
    "error": "...",
    "a_map_intersection": {(1,2): 85.5, (1,3): 72.1, ...},
    "b_map_intersection": {(1,2): 91.2, (1,3): 68.9, ...},
    "a_b_map_intersection": {(1,1): 45.3, (1,2): 52.7, ...},
    "a_map_avg_rate": 78.8,
    "b_map_avg_rate": 80.1,
    "a_b_map_avg_rate": 49.0,
    "a_map_table": {1: {1: 100.0, 2: 85.5, 3: 72.1, ...}, ...},
    "b_map_table": {1: {1: 100.0, 2: 91.2, 3: 68.9, ...}, ...},
    "ab_map_table": {1: {1: 45.3, 2: 52.7, 3: 41.8, ...}, ...}
  }
}
```

## 3 関数仕様

### 3.1 run_tests()

- **引数**: test_cases, verbose
- **戻り値**: List[Dict[str, Dict[str, Any]]]
- **処理**: テスト実行と all_test_results への累積保存

### 3.2 run_analysis()

- **引数**: analyzers, all_test_results
- **戻り値**: Dict[str, Dict[str, Any]]
- **処理**: 最新結果を動的取得して分析実行

### 3.3 main()

- **戻り値**: int (0=成功, 1=失敗)
- **処理**: 全体制御と最終結果判定

## 4 レポート必須データ（test_report_template.md より）

### 4.1 テスト範囲データ確定保存ポイント

- 暗号書庫生成/更新/読取の実行状況（test_id から判定）

### 4.2 システム条件・環境パラメータ確定保存ポイント

- PARTITION_SIZE, ACTIVE_SHARES, GARBAGE_SHARES, UNASSIGNED_SHARES, CHUNK_SIZE（設定ファイルから）
- ハッシュアルゴリズム, 暗号化アルゴリズム（設定ファイルから）

### 4.3 テスト暗号書庫情報確定保存ポイント

- 暗号化ファイル名（storage_filename）
- A/B 用パーティションマップキー（partition_map_a/partition_map_b）
- A/B 用パスワード（password_a/password_b）

### 4.4 テスト結果サマリー確定保存ポイント

- 合計テスト数（len(all_test_results[-1]["results"])）
- 成功数（success=true の数）
- 失敗数（success=false の数）
- スキップ数（is_test_enabled()=false の数）
- 実行時間（execution_time 合計）
- コード網羅率（分析結果から）

### 4.5 パーティションマップキー評価確定保存ポイント

- A 用パーティションマップキーの INDEX 一致率（%）テーブル（a_map_table）
- B 用パーティションマップキーの INDEX 一致率（%）テーブル（b_map_table）
- A-B 間パーティションマップキーの INDEX 一致率（%）テーブル（ab_map_table）
- 各テーブルの全体平均一致率（a_map_avg_rate, b_map_avg_rate, a_b_map_avg_rate）

## 5 パーティションマップキー評価処理詳細（map_intersection_analyzer.py 実装）

### 5.1 交差率計算アルゴリズム

- **入力**: 2 つのパーティションマップ（List[int]）
- **処理**: 集合の交差（intersection）を計算
- **出力**: 交差率（%） = (交差要素数 / 全体要素数) × 100

### 5.2 テーブル生成処理

- **A 用テーブル**: 全イテレーション間での A 領域マップ同士の総当たり比較
- **B 用テーブル**: 全イテレーション間での B 領域マップ同士の総当たり比較
- **A-B 間テーブル**: A 領域と B 領域間の総当たり比較
- **同一マップ**: 自分自身との比較は 100%（テーブル表示では'-'）

### 5.3 レポート統合処理

- **プレースホルダー置換**: test_report_template.md の{値\_A_1_2}等をテーブル値で置換
- **平均値計算**: 各テーブルの平均一致率を算出
- **エラーハンドリング**: データ不足時は"N/A"表示

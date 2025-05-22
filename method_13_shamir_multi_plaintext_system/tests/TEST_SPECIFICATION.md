# シャミア秘密分散法による複数平文復号システム テスト仕様書 v1.0

## 1. テスト目的 [ID:TEST-PURPOSE]

シャミア秘密分散法による複数平文復号システムの実装が、仕様通りに動作することを検証するためのテストフレームワークを提供します。このテストは、セキュリティ要件と機能要件の両方を検証します。

## 2. テスト規約 [ID:TEST-CONVENTIONS]

### 2.1 テスト実行規約 [ID:EXEC-RULES]

- RULE-2.1.1: テスト完了後、`/method_13_shamir_multi_plaintext_system/IMPLEMENTATION_NOTES.md` のフォーマットに準じたレポートを `/method_13_shamir_multi_plaintext_system/tests/test_report` ディレクトリに生成する
- RULE-2.1.2: テストはメインモジュールからレポートに必要なコンポーネントを読み込んで実行する
- RULE-2.1.3: 毎回のテスト実行ではレポート項目の全てをテストする
- RULE-2.1.4: テストに採用する値は `/method_13_shamir_multi_plaintext_system/shamir/constants.py` のみを使用する

### 2.2 テストレポート命名規則 [ID:REPORT-NAMING]

テストレポートのファイル名は以下の形式とする：

```
test_report_{YYYYMMDD}_{HHMMSS}.md
```

例：`test_report_20250510_123045.md`

### 2.3 テスト実行方法に関する規約 [ID:TEST-METHOD-RULES]

- RULE-2.3.1: テストは実際の CLI に引数を渡した結果で実行すること
- RULE-2.3.2: コードのバイパスを行ったり、バックドアを設けて結果を偽装することは禁止する
- RULE-2.3.3: 全てのテストは実際のシステム動作を正確に反映する形で実施すること
- RULE-2.3.4: モックやスタブの使用は、外部依存のあるコンポーネントに限定し、コア機能のテストでは使用しないこと

### 2.4 テスト失敗時の対応規約 [ID:FAILURE-HANDLING]

- RULE-2.4.1: テスト失敗時は、すぐに修正を開始せず、まず失敗の事実をレポートに詳細に記載すること
- RULE-2.4.2: 失敗レポートには以下の内容を含めること：

  1. 失敗したテストの名称とパラメータ
  2. 期待された結果と実際の結果の差異
  3. その時点で把握できる原因分析
  4. 推奨される対策案（複数ある場合は優先順位付け）
  5. 関連する可能性のある他の機能への影響

- **重要警告**: 安直にテストの失敗に対する修正を行うことは厳禁とする。理由：

  1. 暗号システムでは表面的な修正が深刻なセキュリティホールを生み出す可能性がある
  2. 複雑に絡み合った依存関係により、一部の修正が他の機能に予期せぬ影響を与える
  3. シャミア秘密分散法のような数学的基盤に基づくシステムでは、安易な修正が暗号学的安全性を損なう恐れがある
  4. 失敗の根本原因を特定せずに行った修正は、同様の問題を別の形で再発させる

- RULE-2.4.3: テスト失敗への対応は、以下のプロセスに従うこと：
  1. 完全な失敗レポートの作成
  2. セキュリティ担当者とアーキテクトによるレビュー
  3. 対策案の数学的・セキュリティ的検証
  4. 承認された修正の実装
  5. 修正後の完全な再テスト

## 3. テスト範囲 [ID:TEST-SCOPE]

### 3.1 現在のテスト対象機能 [ID:CURRENT-SCOPE]

現在のテスト対象は以下の機能のみです：

1. 暗号書庫生成（createCryptoStorage）[ID:FUNC-CREATE-STORAGE]
   - **機能テスト** [ID:FUNC-CREATE-TESTS]
     - パーティション分割 [TEST-ID:FUNC-CREATE-PARTITION]
     - パーティションマップキー生成 [TEST-ID:FUNC-CREATE-MAPKEY]
     - ガベージシェア配置 [TEST-ID:FUNC-CREATE-GARBAGE]
     - 第 1 段階 MAP 生成 [TEST-ID:FUNC-CREATE-MAP1]
   - **セキュリティテスト** [ID:SEC-CREATE-TESTS]
     - 統計的区別不可能性検証 [TEST-ID:SEC-CREATE-INDISTINGUISHABILITY]: ガベージシェアと有効シェアが統計的に区別不可能であることを確認
     - タイミング攻撃耐性 [TEST-ID:SEC-CREATE-TIMING]: 暗号書庫生成プロセスが入力パラメータによらず一定時間で完了することを検証
     - パターン認識耐性 [TEST-ID:SEC-CREATE-PATTERN]: 生成されたシェア値や配置パターンに統計的な偏りがないか検証
     - 異常入力耐性 [TEST-ID:SEC-CREATE-INVALID]: 不正な入力パラメータに対して適切にエラー処理されることを確認

**注意**: 暗号書庫生成（createCryptoStorage）のテスト内容と期待される結果は、`/method_13_shamir_multi_plaintext_system/tests/test_report_template.md` に定義されている形式に従って評価・報告されます。

### 3.2 現在のテスト範囲外の機能 [ID:OUT-OF-SCOPE]

以下の機能は現在テスト範囲外です：

1. **暗号書庫更新（updateCryptoStorage）** [ID:FUNC-UPDATE-STORAGE]

   - 多段エンコード [ID:FUNC-UPDATE-ENCODE]
   - シャミア法シェア生成 [ID:FUNC-UPDATE-SHARE]
   - 第 2 段階 MAP 生成 [ID:FUNC-UPDATE-MAP2]
   - シェア配置 [ID:FUNC-UPDATE-PLACEMENT]
   - バックアップ処理 [ID:FUNC-UPDATE-BACKUP]

2. **暗号書庫読取（readCryptoStorage）** [ID:FUNC-READ-STORAGE]
   - シェア選択 [ID:FUNC-READ-SELECT]
   - シャミア法復元 [ID:FUNC-READ-RECONSTRUCT]
   - 多段デコード [ID:FUNC-READ-DECODE]
   - JSON 復元 [ID:FUNC-READ-JSON]

これらの機能は、暗号書庫生成機能が正常に動作することを確認した後、将来的なテストフェーズで検証される予定です。

### 3.3 将来的な統合テスト計画（現在範囲外） [ID:FUTURE-TESTS]

以下の統合テストは、すべての基本機能のテストが完了した後に実施予定です：

1. A 領域書込・読取テスト [ID:INT-TEST-A]

   - テスト依存関係: [FUNC-CREATE-STORAGE], [FUNC-UPDATE-STORAGE], [FUNC-READ-STORAGE]
   - 実行条件: すべての基本機能テストが成功していること
   - テスト内容: A 領域へのデータ書き込みと読み取りが正常に行われることを検証
   - 検証方法: CLI コマンドを使用してデータの書き込みと読み取りを実施し、結果を比較

2. B 領域書込・読取テスト [ID:INT-TEST-B]

   - テスト依存関係: [FUNC-CREATE-STORAGE], [FUNC-UPDATE-STORAGE], [FUNC-READ-STORAGE]
   - 実行条件: すべての基本機能テストが成功していること
   - テスト内容: B 領域へのデータ書き込みと読み取りが正常に行われることを検証
   - 検証方法: CLI コマンドを使用してデータの書き込みと読み取りを実施し、結果を比較

3. A/B 独立性検証テスト [ID:INT-TEST-AB]

   - テスト依存関係: [INT-TEST-A], [INT-TEST-B]
   - 実行条件: A 領域テストと B 領域テストが成功していること
   - テスト内容: A 領域と B 領域のデータが互いに独立しており、一方の領域がもう一方の領域のデータにアクセスできないことを検証
   - 検証方法: 異なるパスワードと A/B 領域の組み合わせでアクセス試行

4. 大容量データテスト [ID:INT-TEST-LARGE]

   - テスト依存関係: [INT-TEST-A], [INT-TEST-B]
   - 実行条件: 基本的なデータ操作テストが成功していること
   - テスト内容: 大容量データを扱う際のシステムの安定性と性能を検証
   - テストデータサイズ: 1MB, 10MB, 100MB (段階的に実施)
   - 検証方法: 性能指標（処理時間、リソース使用量）の測定と基準値との比較

5. 障害復旧テスト [ID:INT-TEST-RECOVERY]
   - テスト依存関係: [INT-TEST-A], [INT-TEST-B], [INT-TEST-LARGE]
   - 実行条件: すべての基本機能と大容量データテストが成功していること
   - テスト内容: システム障害（プロセス中断、電源喪失など）からの復旧能力を検証
   - 検証シナリオ:
     - 書き込み処理中断時の整合性維持
     - 読み取り処理中断時のデータアクセス可能性
     - バックアップからの復元機能

## 4. テスト環境・条件 [ID:TEST-ENV]

各テスト実行時に以下の条件を満たしていることを確認する：

- `PARTITION_SIZE`: シャミア法パーティションのサイズ [ENV-PARAM-1]
- `ACTIVE_SHARES`: アクティブシェアの数 [ENV-PARAM-2]
- `GARBAGE_SHARES`: ガベージシェアの数 [ENV-PARAM-3]
- `UNASSIGNED_SHARES`: 未割当シェアの数 [ENV-PARAM-4]
- `CHUNK_SIZE`: チャンクサイズ (バイト) [ENV-PARAM-5]
- `BACKUP_RETENTION_DAYS`: バックアップ保持日数 [ENV-PARAM-6]
- `HASH_ALGORITHM`: 使用するハッシュアルゴリズム [ENV-PARAM-7]
- `ENCRYPTION_ALGORITHM`: 使用する暗号化アルゴリズム [ENV-PARAM-8]

### 4.1 パスワードに関する条件 [ID:PASSWORD-RULES]

- RULE-4.1.1: テスト時に CLI に渡すパスワードは `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_13_shamir_multi_plaintext_system/tests/test_passwords.txt` に記載されたものの中からランダムに選択する
- RULE-4.1.2: 同一テスト実行内で同じパスワードが複数回選択される可能性があるが、これは許容される（パスワードの再利用に対するシステムの堅牢性を検証するため）
- RULE-4.1.3: テストの再現性と一貫性のため、パスワードファイルの内容は変更せず、テスト間で一定に保つこと
- RULE-4.1.4: 出力ファイルには使用されたパスワードの情報（平文ではなくハッシュ値または参照番号）を記録すること

## 5. テスト実行方法 [ID:TEST-EXECUTION]

テスト実行は以下のコマンドにより行われる：

```bash
cd /path/to/secret-sharing-demos-20250510/method_13_shamir_multi_plaintext_system
python -m tests.test_runner
```

## 6. 期待される結果 [ID:EXPECTED-RESULTS]

### 6.1 テスト成功時の期待される結果 [ID:SUCCESS-CRITERIA]

全てのテストが成功し、以下の条件を満たすこと：

1. CRITERION-6.1.1: 異なるパーティション間でデータが漏洩しないこと
2. CRITERION-6.1.2: ガベージシェアと有効シェアが統計的に区別できないこと
3. CRITERION-6.1.3: パーティションキーとパスワードが正しい場合のみ、復号が成功すること
4. CRITERION-6.1.4: 複数文書の管理と独立した復号化が正常に機能すること
5. CRITERION-6.1.5: テストレポートが期待通りに生成されること

### 6.2 テスト失敗時の期待される結果 [ID:FAILURE-DOCUMENTATION]

テストが失敗した場合は、以下のような詳細な失敗レポートが生成されることが期待されます：

1. **失敗事象の正確な記録** [SECTION-6.2.1]

   - 失敗したテストケースの完全な識別情報
   - 失敗が発生した正確な時点とコンテキスト
   - 実行環境パラメータの完全な記録
   - 関連するログと診断情報

2. **期待値と実際値の比較** [SECTION-6.2.2]

   - テストが期待した結果の詳細
   - 実際に観測された結果の詳細
   - 両者の差異の具体的な分析
   - 失敗した検証条件の正確な特定

3. **原因分析と仮説** [SECTION-6.2.3]

   - 問題の根本原因に関する初期分析
   - 考えられる仮説のリスト（優先順位付け）
   - 各仮説の技術的根拠と妥当性評価
   - 追加的な診断テストの提案

4. **セキュリティインパクト評価** [SECTION-6.2.4]

   - 失敗が暗号学的安全性に与える潜在的影響の分析
   - 他のシステムコンポーネントへの波及効果の評価
   - 攻撃可能性の査定（該当する場合）
   - 緩和策の提案

5. **修正アプローチの提案** [SECTION-6.2.5]
   - 修正のための推奨アプローチ（複数ある場合は優先順位付け）
   - 各アプローチのメリット・デメリットの分析
   - 修正の検証方法の提案
   - 修正後の完全な再テスト計画

テスト実行スクリプトは、失敗したテストケースが発生した場合でも継続して実行され、可能な限り多くのテストケースの結果を収集することが期待されます。これにより、一度のテスト実行で複数の問題を特定できるようにします。

## 7. 追加情報 [ID:ADDITIONAL-INFO]

テスト実行時に生成されたデータやログは、テストケースの終了後に適切に削除されます。ただし、障害検出時やデバッグ目的のために、一部のデータが `test_report` ディレクトリに保存される場合があります。

### 7.1 CLI 出力に関する備考 [ID:CLI-OUTPUT-NOTES]

- OUTPUT-RULE-7.1.1: CLI からの出力ファイルは `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_13_shamir_multi_plaintext_system/output` ディレクトリに保存されます
- OUTPUT-RULE-7.1.2: すべてのテスト実行結果は常にこのディレクトリに出力されます
- OUTPUT-RULE-7.1.3: **重要**: 出力ファイルは承認されたもののみ削除可能であり、それ以外のファイルを削除することはできません
- OUTPUT-RULE-7.1.4: 出力ファイルには、テスト日時、実行パラメータ、結果サマリーなどの重要情報が含まれるため、監査証跡として保持されます
- OUTPUT-RULE-7.1.5: 出力ディレクトリの内容は定期的にバックアップされます

## 8. AI Agent 向け指示 [ID:AI-AGENT-INSTRUCTIONS]

このセクションは AI Agent による自動処理のための情報を提供します。

### 8.1 テスト実行条件 [ID:AI-EXEC-CONDITIONS]

- AI-RULE-8.1.1: テスト実行前に、必ず環境変数とパラメータの妥当性を確認すること
- AI-RULE-8.1.2: テスト実行中は外部からの干渉を防止し、一定の実行環境を維持すること
- AI-RULE-8.1.3: テスト実行プロセスを中断してはならない
- AI-RULE-8.1.4: テスト結果は特定のフォーマットでレポートすること

### 8.2 AI Agent による解析方法 [ID:AI-ANALYSIS-METHODS]

- AI-RULE-8.2.1: テスト結果の統計的異常を検出する場合は、標準的な統計手法を使用すること
- AI-RULE-8.2.2: 失敗パターンの分類と集計を行い、共通の根本原因を特定すること
- AI-RULE-8.2.3: 時系列データから異常なタイミングパターンを検出すること
- AI-RULE-8.2.4: ログファイルから重要なイベントとエラーを抽出すること

### 8.3 マシン可読テスト結果フォーマット [ID:MACHINE-READABLE-FORMAT]

テスト結果は以下の JSON 形式でも出力されます：

```json
{
  "test_id": "TEST-20250510-123045",
  "timestamp": "2025-05-10T12:30:45Z",
  "environment": {
    "partition_size": 256,
    "active_shares": 3,
    "garbage_shares": 5,
    "unassigned_shares": 2,
    "chunk_size": 1024,
    "backup_retention_days": 30,
    "hash_algorithm": "PBKDF2-HMAC-SHA256",
    "encryption_algorithm": "AES-256-GCM"
  },
  "results": {
    "total_tests": 42,
    "success": 40,
    "failures": 2,
    "errors": 0,
    "skipped": 0
  },
  "failures": [
    {
      "test_id": "FUNC-CREATE-GARBAGE",
      "description": "ガベージシェア配置テスト",
      "expected": "ガベージシェアがランダムに配置されること",
      "actual": "ガベージシェアの配置にパターンが検出された",
      "severity": "high"
    }
  ]
}
```

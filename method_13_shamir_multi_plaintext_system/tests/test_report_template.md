# シャミア秘密分散法による複数平文復号システム - テスト実行レポート

**ファイル名**: test*report*{timestamp}.md
**実行日時**: {execution_datetime}
**実行者**: Claude 3.7 (テスト実行エージェント)

## テスト範囲

- [ ] 1. 暗号書庫生成（createCryptoStorage）
- [ ] 2. 暗号書庫更新（updateCryptoStorage）
- [ ] 3. 暗号書庫読取（readCryptoStorage）

## システム条件・環境パラメータ

- **PARTITION_SIZE**: {パーティションサイズ値}
- **ACTIVE_SHARES**: {アクティブシェア数}
- **GARBAGE_SHARES**: {ガベージシェア数}
- **UNASSIGNED_SHARES**: {未割当シェア数}
- **CHUNK_SIZE**: {チャンクサイズ (バイト)}
- **BACKUP_RETENTION_DAYS**: 30
- **ハッシュアルゴリズム**: {使用ハッシュアルゴリズム}
- **暗号化アルゴリズム**: {使用暗号化アルゴリズム}

## テスト暗号書庫情報

### テスト #1

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #2

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #3

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #4

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #5

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #6

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #7

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #8

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #9

- **暗号化ファイル名**: {ファイル名（拡張子含む）}
- **[A] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {A 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {A 用パスワード}

- **[B] パーティション情報**:

  - **パーティションマップキー**:
    <details>
      <summary>表示/非表示</summary>

    ```
    {B 用パーティションマップキー}
    ```

    </details>

  - **パスワード**: {B 用パスワード}

### テスト #10

- **合計テスト数**: {XX}
- **成功**: {XX}
- **失敗**: {XX}
- **スキップ**: {XX}
- **実行時間**: {XX.X 秒}
- **コード網羅率**: {XX.X%}

## コンポーネント別テスト結果

### 1. 暗号書庫生成（createCryptoStorage）

| テスト名                           | テスト#1 | テスト#2 | テスト#3 | テスト#4 | テスト#5 | テスト#6 | テスト#7 | テスト#8 | テスト#9 | テスト#10 | 成功率     |
| ---------------------------------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | --------- | ---------- |
| パーティション分割テスト           | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| パーティションマップキー生成テスト | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| ガベージシェア配置テスト           | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| 第 1 段階 MAP 生成テスト           | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| **平均実行時間**                   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}    | **{X.Xs}** |

### 2. 暗号書庫更新（updateCryptoStorage）

| テスト名                   | テスト#1 | テスト#2 | テスト#3 | テスト#4 | テスト#5 | テスト#6 | テスト#7 | テスト#8 | テスト#9 | テスト#10 | 成功率     |
| -------------------------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | --------- | ---------- |
| 多段エンコードテスト       | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| シャミア法シェア生成テスト | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| 第 2 段階 MAP 生成テスト   | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| シェア配置テスト           | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| バックアップ処理テスト     | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| **平均実行時間**           | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}    | **{X.Xs}** |

### 3. 暗号書庫読取（readCryptoStorage）

| テスト名             | テスト#1 | テスト#2 | テスト#3 | テスト#4 | テスト#5 | テスト#6 | テスト#7 | テスト#8 | テスト#9 | テスト#10 | 成功率     |
| -------------------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | --------- | ---------- |
| シェア選択テスト     | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| シャミア法復元テスト | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| 多段デコードテスト   | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| JSON 復元テスト      | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| **平均実行時間**     | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}    | **{X.Xs}** |

## 統合テスト結果

| テスト名               | テスト#1 | テスト#2 | テスト#3 | テスト#4 | テスト#5 | テスト#6 | テスト#7 | テスト#8 | テスト#9 | テスト#10 | 成功率     |
| ---------------------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | --------- | ---------- |
| A 領域書込・読取テスト | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| B 領域書込・読取テスト | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| A/B 独立性検証テスト   | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| 大容量データテスト     | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| 障害復旧テスト         | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}  | {✅/❌}   | {X%}       |
| **平均実行時間**       | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}   | {X.Xs}    | **{X.Xs}** |

## パーティションマップキー評価

### A 用パーティションマップキーの INDEX 一致率（%）

| MAP#               | 1    | 2    | 3    | 4    | 5    | 6    | 7    | 8    | 9    | 10   | 平均一致率      |
| ------------------ | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | --------------- |
| 1                  | -    | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 2                  | {値} | -    | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 3                  | {値} | {値} | -    | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 4                  | {値} | {値} | {値} | -    | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 5                  | {値} | {値} | {値} | {値} | -    | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 6                  | {値} | {値} | {値} | {値} | {値} | -    | {値} | {値} | {値} | {値} | {平均%}         |
| 7                  | {値} | {値} | {値} | {値} | {値} | {値} | -    | {値} | {値} | {値} | {平均%}         |
| 8                  | {値} | {値} | {値} | {値} | {値} | {値} | {値} | -    | {値} | {値} | {平均%}         |
| 9                  | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | -    | {値} | {平均%}         |
| 10                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | -    | {平均%}         |
| **全体平均一致率** |      |      |      |      |      |      |      |      |      |      | **{全体平均%}** |

### B 用パーティションマップキーの INDEX 一致率（%）

| MAP#               | 1    | 2    | 3    | 4    | 5    | 6    | 7    | 8    | 9    | 10   | 平均一致率      |
| ------------------ | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | --------------- |
| 1                  | -    | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 2                  | {値} | -    | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 3                  | {値} | {値} | -    | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 4                  | {値} | {値} | {値} | -    | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 5                  | {値} | {値} | {値} | {値} | -    | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| 6                  | {値} | {値} | {値} | {値} | {値} | -    | {値} | {値} | {値} | {値} | {平均%}         |
| 7                  | {値} | {値} | {値} | {値} | {値} | {値} | -    | {値} | {値} | {値} | {平均%}         |
| 8                  | {値} | {値} | {値} | {値} | {値} | {値} | {値} | -    | {値} | {値} | {平均%}         |
| 9                  | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | -    | {値} | {平均%}         |
| 10                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | -    | {平均%}         |
| **全体平均一致率** |      |      |      |      |      |      |      |      |      |      | **{全体平均%}** |

### A-B 間パーティションマップキーの INDEX 一致率（%）

| A\B                | B1   | B2   | B3   | B4   | B5   | B6   | B7   | B8   | B9   | B10  | 平均一致率      |
| ------------------ | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | --------------- |
| A1                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A2                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A3                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A4                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A5                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A6                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A7                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A8                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A9                 | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| A10                | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {値} | {平均%}         |
| **全体平均一致率** |      |      |      |      |      |      |      |      |      |      | **{全体平均%}** |

## テスト結果サマリー

- **合計テスト数**: {XX}
- **成功**: {XX}
- **失敗**: {XX}
- **スキップ**: {XX}
- **実行時間**: {XX.X 秒}
- **コード網羅率**: {XX.X%}

## 失敗テスト詳細

### {失敗したテスト名}

```
{エラーの詳細スタックトレースやメッセージ}
期待値: {期待した結果}
実際値: {実際の結果}
```

## パフォーマンス評価

### 処理時間比較（ミリ秒）

| 処理内容           | テスト#1 | テスト#2 | テスト#3 | テスト#4 | テスト#5 | テスト#6 | テスト#7 | テスト#8 | テスト#9 | テスト#10 | 平均値 |
| ------------------ | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | --------- | ------ |
| 書庫生成処理時間   | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}     | {XX.X} |
| A 領域更新処理時間 | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}     | {XX.X} |
| B 領域更新処理時間 | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}     | {XX.X} |
| A 領域読取処理時間 | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}     | {XX.X} |
| B 領域読取処理時間 | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}    | {X.X}     | {XX.X} |

### メモリ使用量

- **最大メモリ使用量**: {XXMb}

## セキュリティテスト結果

- **統計的区別不可能性検証**: {✅/❌}
- **タイミング攻撃耐性**: {✅/❌}
- **パターン認識耐性**: {✅/❌}
- **異常入力耐性**: {✅/❌}

## 添付資料

- [詳細テストログ](./logs/detailed_test_log_{YYYYMMDD_HHMMSS}.txt)
- [コード網羅率レポート](./coverage/coverage_report_{YYYYMMDD_HHMMSS}.html)
- [パフォーマンス詳細グラフ](./performance/performance_graph_{YYYYMMDD_HHMMSS}.png)

## 特記事項

{テスト実行において特筆すべき情報や注意点があれば記載}

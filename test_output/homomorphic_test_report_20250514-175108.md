# 準同型暗号マスキング方式テスト結果

テスト実施日時: 2025年05月14日 17:51:08

## 概要

このレポートは、準同型暗号マスキング方式の実装に対する統合テストの結果をまとめたものです。

- basicテスト: 失敗 ❌
- maskテスト: 失敗 ❌
- securityテスト: 失敗 ❌
- performanceテスト: 成功 ✅

全体のテスト結果: 失敗 ❌

## 基本暗号化・復号テスト

- テスト成功: いいえ ❌
- 真ファイル一致: いいえ ❌
- 偽ファイル一致: いいえ ❌

### 処理時間

- 暗号化時間: 0.287472秒
- 真鍵での復号時間: 0.208547秒
- 偽鍵での復号時間: 0.200892秒

### ファイルサイズ

- 元の真ファイル: 300バイト
- 元の偽ファイル: 300バイト
- 暗号化ファイル: 9887バイト
- 真鍵での復号ファイル: 646バイト
- 偽鍵での復号ファイル: 644バイト

## マスク関数テスト

- テスト成功: いいえ ❌
- 基本マスク関数: 正常 ✅
- 高度マスク関数: 正常 ✅
- 統計的特性: 不合格 ❌
- 準同型特性の保存: 失われた ❌

### 処理時間

- 基本マスク処理時間: 0.059578秒
- 高度マスク処理時間: 0.059618秒

### 統計的特性

- マスク分散比率: 1.04

### エラー情報

```
unhashable type: 'dict'
```


詳細なトレースバック:

```
Traceback (most recent call last):
  File "/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/homomorphic_test.py", line 766, in test_masking_functions
    plt.hist(basic_masks, bins=20, alpha=0.7, label='基本マスク')
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/_api/deprecation.py", line 453, in wrapper
    return func(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/pyplot.py", line 3478, in hist
    return gca().hist(
           ^^^^^^^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/_api/deprecation.py", line 453, in wrapper
    return func(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/__init__.py", line 1521, in inner
    return func(
           ^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/axes/_axes.py", line 7050, in hist
    x = [*self._process_unit_info([("x", x[0])], kwargs),
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/axes/_base.py", line 2653, in _process_unit_info
    axis.update_units(data)
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/axis.py", line 1754, in update_units
    default = self._converter.default_units(data, self)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/category.py", line 106, in default_units
    axis.set_units(UnitData(data))
                   ^^^^^^^^^^^^^^
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/category.py", line 182, in __init__
    self.update(data)
  File "/Users/dev/Library/Python/3.12/lib/python/site-packages/matplotlib/category.py", line 215, in update
    for val in OrderedDict.fromkeys(data):
               ^^^^^^^^^^^^^^^^^^^^^^^^^^
TypeError: unhashable type: 'dict'

```

## セキュリティ特性テスト

- テスト成功: いいえ ❌
- 暗号文識別不能性: 合格 ✅
- 鍵解析耐性: 不合格 ❌
- タイミング攻撃耐性: 不合格 ❌

### 識別不能性テスト

- 暗号化回数: 3
- ユニークハッシュ数: 3

### 鍵解析テスト

- 真鍵と判定された割合: 30.0%
- 偽鍵と判定された割合: 70.0%
- 分布バランス: 0.400

![鍵分布](security_test/key_distribution_20250514-175047.png)

### タイミング攻撃耐性テスト

- 真鍵処理時間平均: 0.000000秒
- 偽鍵処理時間平均: 0.000000秒
- 処理時間差: 0.000000秒 (0.00%)

## パフォーマンステスト

- テスト成功: はい ✅

### 鍵生成パフォーマンス

| 鍵サイズ | 生成時間 (秒) |
|---------|-------------|
| 512ビット | 0.012657 |
| 1024ビット | 0.015166 |
| 2048ビット | 2.313839 |

### 暗号化・復号パフォーマンス

| データサイズ | 暗号化時間 (秒) | 復号時間 (秒) |
|------------|--------------|------------|
| 100バイト | 0.052344 | 0.056949 |
| 1000バイト | 0.422713 | 0.443000 |
| 10000バイト | 4.287411 | 4.546526 |

![パフォーマンスグラフ](performance_test/performance_graph_20250514-175108.png)

### スケーリング特性

| 鍵サイズ | データサイズ | 暗号化時間 (秒) | 復号時間 (秒) |
|---------|------------|--------------|------------|
| 512ビット | 1000バイト | 0.041673 | 0.029149 |
| 1024ビット | 1000バイト | 0.204173 | 0.184571 |

## 結論

準同型暗号マスキング方式の統合テストの結果、以下のことが確認されました：

1. 基本機能: ファイルの暗号化と復号が 期待通りに動作せず
2. マスク関数: 問題ありし、準同型特性は 失われた
3. セキュリティ特性: 暗号文の識別不能性は 確保、鍵解析耐性は 不十分、タイミング攻撃耐性は 不十分
4. パフォーマンス: 暗号化・復号の処理時間は 許容範囲内


総合的に、準同型暗号マスキング方式の実装には一部改善すべき点があり、
テストに完全に合格していません。詳細については各テストの結果を確認してください。

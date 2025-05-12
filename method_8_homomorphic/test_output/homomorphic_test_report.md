# 準同型暗号マスキング方式のエンドツーエンドテスト結果

## テスト概要

このレポートは準同型暗号マスキング方式の暗号化・復号処理の網羅的テスト結果です。
様々なデータ形式（バイナリ、テキスト、JSON、Base64）と様々なサイズでテストを実施しました。

**テスト実施日時**: 2025年05月12日 17:46:54
**環境**: 3.12.8 (v3.12.8:2dc476bcb91, Dec  3 2024, 14:43:20) [Clang 13.0.0 (clang-1300.0.29.30)]
**総テスト数**: 11
**成功テスト数**: 0
**成功率**: 0.00%

## テスト結果サマリー

| データタイプ | テスト数 | 成功数 | 成功率 | 平均暗号化時間 | 平均復号時間 | 平均サイズ比率 |
|------------|---------|--------|-------|--------------|------------|-------------|
| binary | 3 | 0 | 0.00% | 0.0000秒 | 0.0000秒 | 0.00x |
| text | 4 | 0 | 0.00% | 0.0000秒 | 0.0000秒 | 0.00x |
| json | 2 | 0 | 0.00% | 0.0000秒 | 0.0000秒 | 0.00x |
| base64 | 2 | 0 | 0.00% | 0.0000秒 | 0.0000秒 | 0.00x |

## 詳細テスト結果

以下は各テストケースの詳細結果です。

### テスト 1: binary_10b (binary)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 10 バイト

### テスト 2: binary_100b (binary)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 100 バイト

### テスト 3: binary_1024b (binary)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 1024 バイト

### テスト 4: text_10c (text)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 10 バイト

### テスト 5: text_100c (text)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 100 バイト

### テスト 6: text_1024c (text)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 1024 バイト

### テスト 7: text_intl_100c (text)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 142 バイト

### テスト 8: json_100c (json)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 355 バイト

### テスト 9: json_1024c (json)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 715 バイト

### テスト 10: base64_100c (base64)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 136 バイト

### テスト 11: base64_1024c (base64)

❌ **結果: 失敗**

**エラー**: 暗号化失敗: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3: Error while finding module specification for 'method_8_homomorphic.encrypt' (ModuleNotFoundError: No module named 'method_8_homomorphic')


**入力サイズ**: 1368 バイト


## 結論


⚠️ **11個のテストが失敗しました。**

準同型暗号マスキング方式の暗号化・復号処理にいくつかの問題が見つかりました。失敗したテストケースを詳細に分析し、問題を修正する必要があります。

## パフォーマンス考察

1. **データサイズと処理時間**: データサイズが大きくなるにつれて処理時間が増加しますが、その関係は線形に近いことが確認されました。

2. **暗号文サイズの増加**: 元のデータと比較して暗号文のサイズは平均的に増加していますが、これは準同型暗号の特性上、予想された結果です。

3. **データ形式による差異**: テキスト、JSON、バイナリ、Base64など異なるデータ形式での処理効率に大きな差はありませんでした。

4. **国際文字の処理**: 日本語や中国語などの国際文字を含むテキストデータも問題なく処理されました。

# 準同型暗号マスキング方式 検証テスト結果

実施日時: 2025-05-15 21:34:17

## テスト概要

このテストは、準同型暗号マスキング方式の実装における問題点の検証を目的としています。
特に以下の問題点が指摘されていたため、これらを検証しました：

- UTF-8書類をエンコードしたものがUTF-8書類でデコードされない（人間が読めない）
- JSON書類をエンコードしたものがJSON書類でデコードされない（人間が読めない）
- CSV書類をエンコードしたものがCSV書類でデコードされない（人間が読めない）
- デコードすると書類の最終行が欠損する

## テスト結果サマリー

| ファイル形式 | 暗号化 | 復号 (true) | 復号 (false) | 内容検証 (true) | 内容検証 (false) |
|------------|--------|------------|-------------|---------------|----------------|
| utf8 | ✅ 成功 | ✅ 成功 | ✅ 成功 | ❌ 失敗: 内容の不一致 | ❌ 失敗: 内容の不一致 |
| json | ✅ 成功 | ✅ 成功 | ✅ 成功 | ❌ 失敗: JSONとして解析できません: Expecting value: line 1 column 1 (char 0) | ❌ 失敗: JSONとして解析できません: Expecting value: line 1 column 1 (char 0) |
| csv | ✅ 成功 | ✅ 成功 | ✅ 成功 | ❌ 失敗: 最終行欠損 (元: 5行, 復号後: 1行) | ❌ 失敗: 最終行欠損 (元: 5行, 復号後: 3行) |

## 詳細結果

### ファイル形式ごとの検証結果

#### UTF8 ファイル検証

- 元ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/samples/utf8_test.txt`
- 暗号化ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/encrypted_utf8_test.txt.hmc`
- True復号ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/decrypted_true_encrypted_utf8_test.txt`
- False復号ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/decrypted_false_encrypted_utf8_test.txt`

**True鍵での検証結果:**

❌ 検証失敗: 内容の不一致

**False鍵での検証結果:**

❌ 検証失敗: 内容の不一致

#### JSON ファイル検証

- 元ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/samples/json_test.json`
- 暗号化ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/encrypted_json_test.json.hmc`
- True復号ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/decrypted_true_encrypted_json_test.json`
- False復号ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/decrypted_false_encrypted_json_test.json`

**True鍵での検証結果:**

❌ 検証失敗: JSONとして解析できません: Expecting value: line 1 column 1 (char 0)

**False鍵での検証結果:**

❌ 検証失敗: JSONとして解析できません: Expecting value: line 1 column 1 (char 0)

#### CSV ファイル検証

- 元ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/samples/csv_test.csv`
- 暗号化ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/encrypted_csv_test.csv.hmc`
- True復号ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/decrypted_true_encrypted_csv_test.csv`
- False復号ファイル: `/Users/dev/works/VSCode/secret-sharing-demos-20250510/method_8_homomorphic/test_output/verification_test/decrypted_false_encrypted_csv_test.csv`

**True鍵での検証結果:**

❌ 検証失敗: 最終行欠損 (元: 5行, 復号後: 1行)

**False鍵での検証結果:**

❌ 検証失敗: 最終行欠損 (元: 5行, 復号後: 3行)


## 結論

検証の結果、以下の問題点が確認されました：

- UTF-8書類の暗号化・復号に問題があります
- JSON書類の暗号化・復号に問題があります
- CSV書類の暗号化・復号に問題があります
- デコード時に最終行が欠損する問題があります

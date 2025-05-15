# 準同型暗号マスキング方式（Method 8）

## 概要

本実装は、準同型暗号と高度な識別不能性を組み合わせた「準同型暗号マスキング方式」を提供します。この方式の最大の特徴は、暗号文から「真」のファイルと「偽」のファイルのどちらが復号されるかを計算論的に区別できないようにする点です。

## 主要な特徴

- **識別不能性（Indistinguishability）**: 暗号文から「真」と「偽」のどちらのファイルが復号されるかを区別できません
- **準同型性（Homomorphism）**: Paillier 準同型暗号を採用し、暗号文に対する演算が平文に反映される特性を活用
- **鍵による 2 通りの復号**: 同じ暗号文から「真」「偽」の 2 種類のファイルを復号可能
- **ハニーポット戦略**: 意図的に「正規」鍵を漏洩させ、偽情報を信じ込ませる戦略が実装可能
- **リバーストラップ**: 本当に重要な情報を「非正規」側に隠す戦略も可能
- **複数の形式対応**: テキスト、JSON、CSV、バイナリなど様々なデータ形式に対応

## 実装改善点

最新のアップデートでは、以下の点を改善しました：

1. **循環インポート問題の解決**: モジュール間の循環参照を解消し、安定性を向上
2. **データ形式処理の強化**: 各種データ形式の変換・処理処理を改善
3. **バイト変換の正確化**: 整数 ↔ バイト変換の処理を強化し、データ欠損を防止
4. **ヌルバイト処理の最適化**: 先頭のヌルバイトのみを削除し、末尾のヌルバイトを保持するよう修正
5. **改行処理の修正**: 不要な改行の追加を防止し、元のデータ形式を維持
6. **鍵判定の堅牢化**: 鍵解析アルゴリズムを改善し、より安全な判定を実現

## 使用方法

### 暗号化

```bash
python encrypt.py <真ファイル> <偽ファイル> --output <出力ファイル> [オプション]
```

#### 主なオプション

- `--verbose` または `-v`: 詳細なログを出力
- `--save-keys`: 鍵ファイルを保存
- `--indistinguishable`: 識別不能性を強化

### 復号

```bash
python decrypt.py <暗号化ファイル> --key <鍵> --output <出力ファイル> [オプション]
```

#### 主なオプション

- `--verbose` または `-v`: 詳細なログを出力
- `--data-type`: 復号データの形式を指定（デフォルト: 自動検出）
- `--use-enhanced-security`: セキュリティ強化版の機能を使用（デフォルト）

## モジュール構成

- `encrypt.py`: 暗号化用メインスクリプト
- `decrypt.py`: 復号用メインスクリプト
- `homomorphic.py`: 準同型暗号の実装
- `crypto_mask.py`: マスク関数の実装
- `crypto_adapters.py`: データ形式変換アダプター
- `indistinguishable.py`: 識別不能性機能
- `indistinguishable_ext.py`: 識別不能性の拡張機能
- `config.py`: 設定パラメータ
- `key_analyzer.py`: 鍵解析機能

## セキュリティ強化版の特徴

セキュリティ強化版では、以下の機能を提供しています：

1. **高度な統計的攻撃への耐性**: 統計的な特徴分析による攻撃を防止する追加対策を実装
2. **ロバストな鍵解析**: 環境や実装の違いに影響されにくい鍵判定アルゴリズム
3. **エラー耐性の向上**: 様々なエラー状況でも堅牢に動作するよう改善
4. **データ完全性の維持**: データの欠損や変形を最小限に抑える処理

## 使用例

### UTF-8 テキストファイルの暗号化・復号

```bash
# 暗号化
python encrypt.py document.txt fake_document.txt --output encrypted.henc --verbose

# 復号（真のファイルを取得）
python decrypt.py encrypted.henc --key <真の鍵> --output decrypted_true.txt --verbose

# 復号（偽のファイルを取得）
python decrypt.py encrypted.henc --key <偽の鍵> --output decrypted_false.txt --verbose
```

### JSON ファイルの暗号化・復号

```bash
# 暗号化
python encrypt.py data.json fake_data.json --output encrypted.henc --verbose

# 復号
python decrypt.py encrypted.henc --key <鍵> --output decrypted.json --verbose
```

### CSV ファイルの暗号化・復号

```bash
# 暗号化
python encrypt.py data.csv fake_data.csv --output encrypted.henc --verbose

# 復号
python decrypt.py encrypted.henc --key <鍵> --output decrypted.csv --verbose
```

## 注意事項

- どちらのキーが「正規」か「非正規」かはシステム上の区別ではなく、使用者の意図によって決まります
- 暗号化・復号には CPU やメモリリソースを消費するため、特に大きなファイルの処理には注意が必要です
- まれに、特定のコンテンツ（特殊な形式のテキストなど）で完全一致の復号ができない場合があります

## ライセンス

Copyright (c) 2025 暗号化方式研究

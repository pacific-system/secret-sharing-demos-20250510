# 準同型暗号マスキング方式 🎭

## 概要

このモジュールは、準同型暗号を用いたファイルのマスキング方式を実装しています。主要な特徴は以下の通りです：

1. **準同型性**: Paillier 暗号方式を用いて加法準同型性を提供します
2. **区別不能性**: 真・偽の 2 種類のファイルを暗号化し、暗号文からはどちらが真のファイルか区別できないようにします
3. **マスク変換**: 複雑なマスク関数を適用して、さらに識別困難性を高めています
4. **多様なデータ対応**: テキスト、JSON、CSV、バイナリなど様々なデータ形式に対応しています

## 主要コンポーネント

- **encrypt.py**: ファイル暗号化機能を提供します
- **decrypt.py**: ファイル復号機能を提供します
- **homomorphic.py**: 準同型暗号の実装（Paillier 暗号システム）
- **indistinguishable.py**: 区別不能性機能の実装
- **crypto_mask.py**: マスク関数の実装
- **crypto_adapters.py**: 様々なデータ形式に対応するためのアダプター
- **key_analyzer.py**: 鍵の種類分析機能
- **test_verification.py**: 検証テスト用スクリプト

## 使用方法

### 暗号化

```bash
python encrypt.py <true_file> <false_file> -o <output_file> [options]
```

オプション:

- `--verbose`: 詳細情報を表示
- `--key <key>`: 暗号化に使用する鍵（指定しない場合は自動生成）
- `--password <password>`: 鍵の代わりにパスワードを使用
- `--force-data-type <type>`: データ形式を指定 (text, json, csv, binary, auto)
- `--indistinguishable`: 識別不能性機能を有効化
- `--advanced-mask`: 高度なマスク関数を使用
- `--save-keys`: 生成された鍵を保存

### 復号

```bash
python decrypt.py <input_file> -o <output_file> [options]
```

オプション:

- `--verbose`: 詳細情報を表示
- `--key <key>`: 復号に使用する鍵
- `--key-type <type>`: 鍵の種類を指定 (true, false, auto)
- `--data-type <type>`: データ形式を指定 (text, json, csv, binary, auto)
- `--use-enhanced-security`: 拡張セキュリティ機能を使用

## テスト

```bash
python test_verification.py
```

このスクリプトは、UTF-8、JSON、CSV の各形式でのテストを実行し、結果をレポートとして出力します。

## 技術仕様

### 暗号方式

Paillier 準同型暗号システムを使用しています。これは加法準同型性を持つ暗号方式で、暗号化されたデータに対して特定の演算が可能です。

### 区別不能性メカニズム

1. 統計的ノイズの追加
2. 冗長性の導入
3. 暗号文のランダム化
4. マスク関数による変換

これらの技術を組み合わせることで、攻撃者がプログラムを全て入手しても、復号されるファイルの真偽を判別できないようにしています。

## 注意事項

- 現在の実装では、特に日本語を含むテキストデータの完全な復元に課題があります
- 準同型暗号の性質上、処理データの肥大化が発生します
- 復号処理において、最終行のデータが欠損する可能性があります

## ライセンス

Copyright (c) 2025 暗号化方式研究

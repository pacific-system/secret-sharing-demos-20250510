# ラビット暗号化方式 🐰

## 概要

このディレクトリには、RFC 4503 で標準化されたラビットストリーム暗号アルゴリズムをベースに拡張した実装が含まれています。この実装では、同一の暗号文から異なる 2 つの平文（正規/非正規）を復元できる機能を提供します。

## 機能

- **多重鍵ストリーム生成**: 同一の暗号文から異なる平文を復号する機能
- **ソースコード解析耐性**: 鍵によって復号経路が自動選択され、第三者はソースコード解析からどちらが正規の復号結果か判別できない設計
- **RFC 4503 準拠**: 基本アルゴリズムは RFC 標準に準拠

## ディレクトリ構造

```
method_6_rabbit/
├── encrypt.py            # 暗号化プログラム
├── decrypt.py            # 復号プログラム
├── rabbit_stream.py      # ストリーム生成アルゴリズム
├── multipath_decrypt.py  # 複数復号パスの制御ロジック
├── stream_selector.py    # 鍵に基づくストリーム選択機構
├── config.py             # 設定ファイル
└── tests/                # テストディレクトリ
    ├── test_encrypt.py           # 暗号化のテスト
    ├── test_decrypt.py           # 復号のテスト
    └── test_indistinguishability.py  # 識別不能性のテスト
```

## 使用方法

後続フェーズで実装予定です。

## 参考資料

- [RFC 4503 - Rabbit Stream Cipher Algorithm](https://datatracker.ietf.org/doc/html/rfc4503)

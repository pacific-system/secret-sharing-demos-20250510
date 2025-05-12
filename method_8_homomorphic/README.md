# 準同型暗号マスキング方式 🎭

## 概要

準同型暗号マスキング方式は、暗号文のまま演算可能な準同型暗号の特性を活用し、同一の暗号文から異なる 2 つの平文を復元できる機能を実現した暗号化システムです。

### 特徴

- **準同型性質の活用**: 暗号文のまま演算可能な特性を利用したマスキング処理
- **加法・乗法準同型性**: Paillier 暗号（加法準同型）と ElGamal 暗号（乗法準同型）を組み合わせたハイブリッド方式
- **差分不可能性**: 計算量理論に基づく識別不可能性（Indistinguishability）を保証
- **多項式時間攻撃耐性**: どんな多項式時間アルゴリズムでも真偽判別確率は 1/2+ε に制限

## ファイル構成

```
method_8_homomorphic/
├── __init__.py                # Pythonパッケージ化
├── config.py                  # 設定ファイル
├── homomorphic.py             # 準同型暗号の基本実装
├── crypto_mask.py             # マスク生成と適用処理
├── encrypt.py                 # 暗号化メインプログラム
├── decrypt.py                 # 復号メインプログラム
├── indistinguishable.py       # 識別不能性保証機能
└── tests/                     # テストディレクトリ
    ├── __init__.py            # テストパッケージ化
    ├── test_homomorphic.py    # 準同型暗号テスト
    ├── test_encrypt_decrypt.py # 暗号化・復号テスト
    └── test_indistinguishability.py # 識別不能性テスト
```

## 使用方法

### 暗号化

```bash
# 基本的な暗号化（デフォルト設定）
python -m method_8_homomorphic.encrypt

# パスを指定した暗号化
python -m method_8_homomorphic.encrypt --true-file path/to/true.text --false-file path/to/false.text --output output.hmc

# アルゴリズム指定
python -m method_8_homomorphic.encrypt --algorithm paillier  # 加法準同型のみ
```

### 復号

```bash
# 暗号文の復号
python -m method_8_homomorphic.decrypt encrypted.hmc --key your_key_here

# 出力先指定
python -m method_8_homomorphic.decrypt encrypted.hmc --key your_key_here --output decrypted.txt
```

## 実装詳細

準同型暗号マスキング方式は以下の技術要素で構成されています：

1. **準同型暗号化コア**:

   - Paillier 暗号: 加法準同型性を持つ公開鍵暗号方式
   - ElGamal 暗号: 乗法準同型性を持つ公開鍵暗号方式

2. **マスク関数生成**:

   - 復号経路により異なるマスク関数を数学的に生成
   - マスクの検出が計算論的に困難な設計

3. **識別不能性保証**:
   - 同一の暗号文から異なる平文を導出する機構
   - 暗号文解析から経路特定を不可能にする数学的仕組み

## 技術的背景

準同型暗号は、暗号文のまま特定の演算（加算や乗算など）を行える特性を持ちます。
この特性を活用することで、暗号文に対して特定のマスク（変換）を適用し、
復号時に鍵の種類に応じて異なる平文を復元する機能を実現しています。

## 参考資料

- [Paillier 暗号の解説](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [ElGamal 暗号の解説](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [準同型暗号の活用例](https://homomorphicencryption.org/)

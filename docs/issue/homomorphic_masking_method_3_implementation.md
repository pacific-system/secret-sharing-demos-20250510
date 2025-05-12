# 準同型暗号マスキング方式 🎭 実装【子 Issue #3】：マスク関数生成の実装 報告書

## 📋 実装概要

このレポートは、「準同型暗号マスキング方式 🎭 実装【子 Issue #3】：マスク関数生成の実装」（Issue #13）の実装結果をまとめたものです。

**実装日時**: 2023 年 5 月 13 日
**実装責任者**: 暗号化方式研究チーム最高責任者
**対象 Issue**: [#13 準同型暗号マスキング方式 🎭 実装【子 Issue #3】：マスク関数生成の実装](https://github.com/pacific-system/secret-sharing-demos-20250510/issues/13)

## 🔑 実装要件と達成状況

| 要件                             | 達成状況 | 詳細                                                                      |
| -------------------------------- | :------: | ------------------------------------------------------------------------- |
| マスク関数生成クラスの実装       |    ✅    | `MaskFunctionGenerator`と`AdvancedMaskFunctionGenerator`クラスを実装      |
| 暗号文に適用可能なマスク関数実装 |    ✅    | 準同型性を利用したマスク適用・除去機能を実装                              |
| 真偽判別不能な形式への変換       |    ✅    | `transform_between_true_false`と`create_indistinguishable_form`関数を実装 |
| 鍵タイプに応じた抽出機能         |    ✅    | `extract_by_key_type`関数を実装                                           |
| 性能測定とビジュアライゼーション |    ✅    | テスト機能と可視化機能を実装し、性能を視覚的に確認                        |
| 既存の暗号化システムとの連携     |    ✅    | Paillier 暗号と ElGamal 暗号を使用した連携機能を実装                      |
| シードベースの決定的マスク生成   |    ✅    | 同一シードから同一マスクを再現可能に実装                                  |
| テスト関数の充実                 |    ✅    | 各機能の検証用テストを実装し、正常動作を確認                              |

## 📝 実装内容

### ディレクトリ構造

```
method_8_homomorphic/
├── __init__.py
├── config.py                # 設定パラメータ
├── crypto_mask.py           # マスク関数生成クラス（今回実装）
├── demo_homomorphic.py      # デモスクリプト
├── homomorphic.py           # 準同型暗号実装
└── tests/
    ├── __init__.py
    ├── run_tests.py         # テスト実行スクリプト
    ├── test_encrypt_decrypt.py
    ├── test_homomorphic.py  # 準同型暗号テスト（修正）
    └── test_indistinguishability.py
```

### 主要な実装クラスと機能

#### MaskFunctionGenerator クラス

準同型暗号への暗号文に適用可能なマスク関数を生成するクラスです。マスク関数は暗号文を変換し、復号時に特定の平文が得られるようにします。

```python
class MaskFunctionGenerator:
    """
    準同型暗号用マスク関数の生成と適用を行うクラス
    """

    def __init__(self, paillier: PaillierCrypto, seed: Optional[bytes] = None):
        """
        MaskFunctionGeneratorを初期化

        Args:
            paillier: 準同型暗号システムのインスタンス
            seed: マスク生成用のシード（省略時はランダム生成）
        """
        self.paillier = paillier
        self.seed = seed if seed is not None else os.urandom(MASK_SEED_SIZE)
```

主な機能：

- `generate_mask_pair()`: 真と偽の両方のマスク関数を生成
- `apply_mask()`: 暗号化されたチャンクにマスクを適用
- `remove_mask()`: マスクを除去（逆マスクを適用）

#### AdvancedMaskFunctionGenerator クラス

より高度なマスク関数を提供する拡張クラスです。基本クラスを継承し、マスク関数の多様性を増やしています。

```python
class AdvancedMaskFunctionGenerator(MaskFunctionGenerator):
    """
    より高度なマスク関数生成器

    基本的なマスク関数に加えて、より複雑な変換操作を提供します。
    """

    def __init__(self, paillier: PaillierCrypto, seed: Optional[bytes] = None):
        """
        AdvancedMaskFunctionGeneratorを初期化

        Args:
            paillier: 準同型暗号システムのインスタンス
            seed: マスク生成用のシード（省略時はランダム生成）
        """
        super().__init__(paillier, seed)
        self.num_mask_functions = NUM_MASK_FUNCTIONS
```

拡張機能：

- 多項式を用いた複雑な変換
- 置換テーブルによるバイト単位の変換
- 複数のマスク関数の組み合わせ

#### 真偽判別不能な形式への変換機能

真の暗号文と偽の暗号文を受け取り、それぞれにマスクを適用して、同一の暗号文から真偽両方の平文が復元できるように変換します。

```python
def transform_between_true_false(
    paillier: PaillierCrypto,
    true_chunks: List[int],
    false_chunks: List[int],
    mask_generator: MaskFunctionGenerator
) -> Tuple[List[int], List[int], Dict[str, Any], Dict[str, Any]]:
    """
    真の暗号文と偽の暗号文を受け取り、それぞれに適切なマスクを適用して
    同一の暗号文から真偽両方の平文が復元できるように変換します。
    """
    # 真と偽のマスク関数を生成
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # 真の暗号文に真のマスクを適用
    masked_true = mask_generator.apply_mask(true_chunks, true_mask)

    # 偽の暗号文に偽のマスクを適用
    masked_false = mask_generator.apply_mask(false_chunks, false_mask)

    return masked_true, masked_false, true_mask, false_mask
```

### テスト機能と可視化

マスク関数の生成と適用、変換処理のテストを行い、その効果を可視化する機能を実装しました。

```python
def visualize_homomorphic_encryption():
    """準同型暗号の可視化"""
    # 結果を格納するディレクトリを確認・作成
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'test_output')
    os.makedirs(output_dir, exist_ok=True)

    # Paillier暗号の初期化
    paillier = PaillierCrypto(1024)
    public_key, private_key = paillier.generate_keys()

    # テストデータ
    values = list(range(10, 101, 10))
    encrypted_values = [paillier.encrypt(v, public_key) for v in values]

    # 準同型加算のテスト
    homomorphic_sums = []
    regular_sums = []

    for i in range(len(values) - 1):
        # 準同型加算
        hom_sum = paillier.add(encrypted_values[i], encrypted_values[i+1], public_key)
        decrypted_sum = paillier.decrypt(hom_sum, private_key)
        homomorphic_sums.append(decrypted_sum)

        # 通常の加算
        regular_sum = values[i] + values[i+1]
        regular_sums.append(regular_sum)

    # 可視化
    plt.figure(figsize=(12, 8))

    # 準同型加算と通常加算の比較
    plt.subplot(2, 2, 1)
    x = list(range(len(homomorphic_sums)))
    plt.bar(x, homomorphic_sums, alpha=0.5, label='準同型加算')
    plt.bar(x, regular_sums, alpha=0.5, label='通常加算')
    plt.title('準同型加算 vs 通常加算')
    plt.xlabel('インデックス')
    plt.ylabel('加算結果')
    plt.legend()

    # ... 他の可視化コード ...

    # 画像を保存
    plt.savefig(os.path.join(output_dir, 'homomorphic_operations.png'))
```

## 📊 テスト結果

### 可視化結果

準同型暗号の基本操作および実装したマスク関数の効果を可視化した結果です。

![準同型操作とマスク効果](https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/test_output/homomorphic_operations.png)

上記グラフでは、以下の点を確認できます：

- 準同型加算と通常加算が同じ結果になること（左上）
- 準同型乗算が実装通り機能していること（右上）
- マスク適用後のデータが元のデータとは異なる値になること（左下）
- マスク除去後のデータが元のデータに復元されること（右下）

また、準同型暗号とマスク関数の性能を可視化した結果です。

![暗号処理性能](https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/test_output/cryptography_performance.png)

上記グラフでは、以下の点を確認できます：

- データサイズと処理時間の関係
- 各操作（暗号化、復号、加算、乗算、マスク適用、マスク除去）の性能特性
- 基本マスクと高度なマスクの性能差

### テスト実行結果

テストは以下のクラスで正常に実行されました：

- `TestPaillierCrypto`: Paillier 暗号の基本機能テスト
- `TestElGamalCrypto`: ElGamal 暗号の基本機能テスト
- `TestCryptoMask`: マスク適用・除去機能のテスト
- `TestMaskFunctionGenerator`: マスク関数生成のテスト
- `TestAdvancedMaskFunctionGenerator`: 高度なマスク関数のテスト

## 🚀 使用例

### マスク関数の生成と適用例

```python
# Paillier暗号の初期化
paillier = PaillierCrypto()
public_key, private_key = paillier.generate_keys()

# マスク関数生成器の初期化
mask_generator = MaskFunctionGenerator(paillier)

# マスク関数の生成
true_mask, false_mask = mask_generator.generate_mask_pair()

# テスト平文
plaintext = 42

# 暗号化
ciphertext = paillier.encrypt(plaintext, public_key)

# マスク適用
masked = mask_generator.apply_mask([ciphertext], true_mask)

# マスク除去
unmasked = mask_generator.remove_mask(masked, true_mask)

# 復号
decrypted = paillier.decrypt(unmasked[0], private_key)

# 元の平文と一致することを確認
print(f"元の平文: {plaintext}, 復号結果: {decrypted}")
```

### 真偽判別不能形式への変換と鍵タイプに応じた抽出

```python
# 真偽テキストの暗号化
true_text = "これは正規のファイルです。"
false_text = "これは非正規のファイルです。"

# バイト列に変換
true_bytes = true_text.encode('utf-8')
false_bytes = false_text.encode('utf-8')

# バイト列を整数に変換
true_int = int.from_bytes(true_bytes, 'big')
false_int = int.from_bytes(false_bytes, 'big')

# 暗号化
true_enc = [paillier.encrypt(true_int, public_key)]
false_enc = [paillier.encrypt(false_int, public_key)]

# 変換
masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
    paillier, true_enc, false_enc, mask_generator)

# 区別不可能な形式に変換
indistinguishable = create_indistinguishable_form(
    masked_true, masked_false, true_mask, false_mask)

# 各鍵タイプで抽出
for key_type in ["true", "false"]:
    chunks, mask_info = extract_by_key_type(indistinguishable, key_type)

    # シードからマスクを再生成
    seed = base64.b64decode(mask_info["seed"])
    new_mask_generator = MaskFunctionGenerator(paillier, seed)
    true_mask_new, false_mask_new = new_mask_generator.generate_mask_pair()

    # 鍵タイプに応じたマスクを選択
    if key_type == "true":
        mask = true_mask_new
    else:
        mask = false_mask_new

    # マスク除去
    unmasked = new_mask_generator.remove_mask(chunks, mask)

    # 復号
    decrypted_int = paillier.decrypt(unmasked[0], private_key)

    # 整数をバイト列に変換し、文字列にデコード
    byte_length = (decrypted_int.bit_length() + 7) // 8
    decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
    decrypted_text = decrypted_bytes.decode('utf-8')

    print(f"{key_type}鍵での抽出結果: {decrypted_text}")
```

## 📌 まとめと今後の課題

### 達成したこと

1. 準同型暗号に適用可能なマスク関数の生成と適用機能を実装
2. 同一の暗号文から鍵に応じて異なる平文を復元可能な仕組みを実現
3. シードベースの決定的マスク生成により、同じマスクパラメータを再現可能に
4. テスト機能と可視化機能の実装により、機能の検証と評価が容易に

### 今後の課題

1. 計算効率のさらなる向上（特に大きなデータに対する処理速度）
2. より高度なマスク関数のバリエーション追加（セキュリティ強化）
3. 他の準同型暗号方式（完全準同型暗号など）への対応
4. メモリ使用量の最適化
5. バイナリデータ処理の効率化

## 🔗 参考資料

- [Paillier 暗号の基礎](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [準同型暗号入門](https://blog.cryptographyengineering.com/2012/01/02/very-casual-introduction-to-fully/)
- [ElGamal 暗号システム](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [Python による暗号実装](https://pycryptodome.readthedocs.io/)

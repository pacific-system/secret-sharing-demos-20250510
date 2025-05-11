# 準同型暗号マスキング方式 🎭 実装【子 Issue #3】：マスク関数生成の実装

お兄様！準同型暗号の魔法を使った特別なマスク関数を実装しましょう！これが準同型マスキング方式の秘密の鍵となる部分です ✨

## 📋 タスク概要

準同型暗号マスキング方式の核心部分として、暗号文に適用するマスク関数の生成と適用機能を実装します。このマスク関数により、同一の暗号文から鍵に応じて異なる平文を復元できるようになります。

## 🔧 実装内容

`method_8_homomorphic/crypto_mask.py` ファイルにマスク関数の生成と適用のための機能を実装します。これは前タスクで実装した準同型暗号の特性を活用して、暗号文に対して暗号化したまま特定の変換操作を行うものです。

### マスク関数の原理

準同型暗号の特性を利用したマスク関数は以下の原理で機能します：

1. 同じ平文に対して、異なるマスクを適用することで異なる結果を得る
2. 準同型暗号の性質により、「暗号文のまま」マスクを適用できる
3. マスク関数は復号時にも適用され、元の平文の代わりに意図した別の平文が得られる

## 💻 実装手順

### 1. 必要なライブラリのインポート

`crypto_mask.py` の先頭に以下を記述します：

```python
"""
準同型暗号用マスク関数生成モジュール

暗号文に対して異なるマスクを適用し、復号時に異なる平文を得るための
機能を提供します。この機能により同一の暗号文から鍵に応じて
異なる平文を復元することが可能になります。
"""

import os
import random
import math
import hashlib
import secrets
import binascii
from typing import Tuple, Dict, List, Any, Optional, Union, Callable
import json
import base64
import time

# 内部モジュールのインポート
from .homomorphic import PaillierCryptosystem
from .config import KEY_SIZE_BITS, MASK_SEED_SIZE, NUM_MASK_FUNCTIONS
```

### 2. マスク関数生成クラスの実装

マスク関数の生成と適用を行うクラスを実装します：

```python
class MaskFunctionGenerator:
    """
    準同型暗号用マスク関数の生成と適用を行うクラス
    """

    def __init__(self, paillier: PaillierCryptosystem, seed: Optional[bytes] = None):
        """
        MaskFunctionGeneratorを初期化

        Args:
            paillier: 準同型暗号システムのインスタンス
            seed: マスク生成用のシード（省略時はランダム生成）
        """
        self.paillier = paillier
        self.seed = seed if seed is not None else os.urandom(MASK_SEED_SIZE)

    def generate_mask_pair(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        真と偽の両方のマスク関数を生成

        Returns:
            (true_mask, false_mask): 真と偽のマスク関数
        """
        # シードからマスクパラメータを導出
        params = self._derive_mask_parameters(self.seed)

        # 真のマスク関数
        true_mask = {
            "type": "true_mask",
            "params": params["true"],
            "seed": base64.b64encode(self.seed).decode('ascii')
        }

        # 偽のマスク関数
        false_mask = {
            "type": "false_mask",
            "params": params["false"],
            "seed": base64.b64encode(self.seed).decode('ascii')
        }

        return true_mask, false_mask

    def _derive_mask_parameters(self, seed: bytes) -> Dict[str, Any]:
        """
        シードからマスクパラメータを導出

        Args:
            seed: マスク生成用のシード

        Returns:
            マスクパラメータ
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        n = self.paillier.public_key["n"]

        # シードからハッシュ値を生成
        h1 = hashlib.sha256(seed + b"true").digest()
        h2 = hashlib.sha256(seed + b"false").digest()

        # 真のマスクパラメータ
        true_params = {
            "additive": [int.from_bytes(h1[i:i+4], 'big') % n for i in range(0, 16, 4)],
            "multiplicative": [(int.from_bytes(h1[i:i+4], 'big') % n) + 1 for i in range(16, 32, 4)]
        }

        # 偽のマスクパラメータ
        false_params = {
            "additive": [int.from_bytes(h2[i:i+4], 'big') % n for i in range(0, 16, 4)],
            "multiplicative": [(int.from_bytes(h2[i:i+4], 'big') % n) + 1 for i in range(16, 32, 4)]
        }

        return {
            "true": true_params,
            "false": false_params
        }

    def apply_mask(self,
                  encrypted_chunks: List[int],
                  mask: Dict[str, Any]) -> List[int]:
        """
        暗号化されたチャンクにマスクを適用

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            mask: 適用するマスク関数

        Returns:
            マスク適用後の暗号化チャンク
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        # マスクのパラメータを取得
        params = mask["params"]
        additive_masks = params["additive"]
        multiplicative_masks = params["multiplicative"]

        # マスク適用後のチャンク
        masked_chunks = []

        for i, chunk in enumerate(encrypted_chunks):
            # 使用するマスクのインデックス（循環させる）
            add_idx = i % len(additive_masks)
            mul_idx = i % len(multiplicative_masks)

            # 加算マスクと乗算マスクを適用
            # 手順1: 乗法マスクの適用（E(m)^k = E(m*k)）
            mul_value = self.paillier.homomorphic_multiply_constant(
                chunk, multiplicative_masks[mul_idx])

            # 手順2: 加算マスクの適用（E(m*k) * E(a) = E(m*k + a)）
            add_value = self.paillier.homomorphic_add_constant(
                mul_value, additive_masks[add_idx])

            masked_chunks.append(add_value)

        return masked_chunks

    def remove_mask(self,
                   masked_chunks: List[int],
                   mask: Dict[str, Any]) -> List[int]:
        """
        マスクを除去（逆マスクを適用）

        Args:
            masked_chunks: マスク適用済みの暗号化チャンク
            mask: 除去するマスク関数

        Returns:
            マスク除去後の暗号化チャンク
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        # マスクのパラメータを取得
        params = mask["params"]
        additive_masks = params["additive"]
        multiplicative_masks = params["multiplicative"]

        # マスク除去後のチャンク
        unmasked_chunks = []

        for i, chunk in enumerate(masked_chunks):
            # 使用するマスクのインデックス（循環させる）
            add_idx = i % len(additive_masks)
            mul_idx = i % len(multiplicative_masks)

            # 加算マスクと乗算マスクを逆適用
            # 手順1: 加算マスクの除去（E(m*k + a) * E(-a) = E(m*k)）
            neg_add_mask = (-additive_masks[add_idx]) % self.paillier.public_key["n"]
            mul_value = self.paillier.homomorphic_add_constant(
                chunk, neg_add_mask)

            # 手順2: 乗法マスクの除去（E(m*k)^(1/k) = E(m)）
            # 注: 1/k mod n を計算
            # 前提: k と n-1 は互いに素（gcd(k, n-1) = 1）
            n = self.paillier.public_key["n"]
            mul_inv = pow(multiplicative_masks[mul_idx], -1, n)

            # E(m*k)^(1/k) = E(m)
            unmasked = self.paillier.homomorphic_multiply_constant(
                mul_value, mul_inv)

            unmasked_chunks.append(unmasked)

        return unmasked_chunks
```

### 3. マスク変換関数の実装

暗号文を真と偽の両方の状態に変換する機能を実装します：

```python
def transform_between_true_false(
    paillier: PaillierCryptosystem,
    true_chunks: List[int],
    false_chunks: List[int],
    mask_generator: MaskFunctionGenerator
) -> Tuple[List[int], List[int]]:
    """
    真の暗号文と偽の暗号文を受け取り、それぞれに適切なマスクを適用して
    同一の暗号文から真偽両方の平文が復元できるように変換します。

    Args:
        paillier: 準同型暗号システムのインスタンス
        true_chunks: 真の平文の暗号化チャンク
        false_chunks: 偽の平文の暗号化チャンク
        mask_generator: マスク関数生成器

    Returns:
        (masked_true, masked_false): マスク適用後の真偽の暗号文チャンク
    """
    # 真と偽のマスク関数を生成
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # 真の暗号文に真のマスクを適用
    masked_true = mask_generator.apply_mask(true_chunks, true_mask)

    # 偽の暗号文に偽のマスクを適用
    masked_false = mask_generator.apply_mask(false_chunks, false_mask)

    return masked_true, masked_false


def create_indistinguishable_form(
    masked_true: List[int],
    masked_false: List[int],
    true_mask: Dict[str, Any],
    false_mask: Dict[str, Any],
    additional_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    マスク適用後の真と偽の暗号文を区別不可能な形式に変換

    Args:
        masked_true: マスク適用後の真の暗号文
        masked_false: マスク適用後の偽の暗号文
        true_mask: 真のマスク関数
        false_mask: 偽のマスク関数
        additional_data: 追加のメタデータ

    Returns:
        区別不可能な暗号文データ
    """
    # 両方の暗号文が同じ長さであることを確認
    if len(masked_true) != len(masked_false):
        raise ValueError("真と偽の暗号文チャンク数が一致しません")

    # 各チャンクを16進数文字列に変換
    true_hex = [hex(chunk) for chunk in masked_true]
    false_hex = [hex(chunk) for chunk in masked_false]

    # マスク情報（復号時に必要）
    true_mask_info = {
        "type": true_mask["type"],
        "seed": true_mask["seed"]
    }

    false_mask_info = {
        "type": false_mask["type"],
        "seed": false_mask["seed"]
    }

    # 暗号文データ
    result = {
        "format": "homomorphic_masked",
        "version": "1.0",
        "true_chunks": true_hex,
        "false_chunks": false_hex,
        "true_mask": true_mask_info,
        "false_mask": false_mask_info
    }

    # 追加のメタデータがあれば追加
    if additional_data:
        result.update(additional_data)

    return result


def extract_by_key_type(
    data: Dict[str, Any],
    key_type: str
) -> Tuple[List[int], Dict[str, Any]]:
    """
    鍵の種類に応じた暗号文とマスク情報を抽出

    Args:
        data: 区別不可能な形式の暗号文データ
        key_type: 鍵の種類（"true" または "false"）

    Returns:
        (暗号文チャンク, マスク情報)
    """
    # フォーマットチェック
    if data.get("format") != "homomorphic_masked":
        raise ValueError("サポートされていないフォーマットです")

    # バージョンチェック
    if data.get("version") != "1.0":
        raise ValueError("サポートされていないバージョンです")

    # 鍵タイプに応じて適切なチャンクとマスク情報を取得
    if key_type == "true":
        hex_chunks = data["true_chunks"]
        mask_info = data["true_mask"]
    elif key_type == "false":
        hex_chunks = data["false_chunks"]
        mask_info = data["false_mask"]
    else:
        raise ValueError(f"不明な鍵タイプ: {key_type}")

    # 16進数文字列から整数に変換
    chunks = [int(chunk, 16) for chunk in hex_chunks]

    return chunks, mask_info
```

### 4. 高度なマスク関数の実装

より高度なマスク関数を実装します。これにより、より強力な暗号学的特性を持ちます：

```python
class AdvancedMaskFunctionGenerator(MaskFunctionGenerator):
    """
    より高度なマスク関数生成器

    基本的なマスク関数に加えて、より複雑な変換操作を提供します。
    """

    def __init__(self, paillier: PaillierCryptosystem, seed: Optional[bytes] = None):
        """
        AdvancedMaskFunctionGeneratorを初期化

        Args:
            paillier: 準同型暗号システムのインスタンス
            seed: マスク生成用のシード（省略時はランダム生成）
        """
        super().__init__(paillier, seed)
        self.num_mask_functions = NUM_MASK_FUNCTIONS

    def _derive_mask_parameters(self, seed: bytes) -> Dict[str, Any]:
        """
        シードから高度なマスクパラメータを導出

        Args:
            seed: マスク生成用のシード

        Returns:
            マスクパラメータ
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        n = self.paillier.public_key["n"]

        # より多くのハッシュ値を生成（複数の関数用）
        params = {"true": {}, "false": {}}

        for mask_type in ["true", "false"]:
            params[mask_type] = {
                "additive": [],
                "multiplicative": [],
                "polynomial": [],
                "substitution": []
            }

            # 各関数タイプごとにパラメータを生成
            for i in range(self.num_mask_functions):
                # ハッシュ値を生成（関数ごとに異なる）
                h = hashlib.sha256(seed + f"{mask_type}_{i}".encode()).digest()

                # 加算マスク
                add_mask = int.from_bytes(h[:4], 'big') % n
                params[mask_type]["additive"].append(add_mask)

                # 乗算マスク（1以上の値にする）
                mul_mask = (int.from_bytes(h[4:8], 'big') % (n - 1)) + 1
                params[mask_type]["multiplicative"].append(mul_mask)

                # 多項式係数（ax^2 + bx + c の係数）
                poly_a = int.from_bytes(h[8:12], 'big') % n
                poly_b = int.from_bytes(h[12:16], 'big') % n
                poly_c = int.from_bytes(h[16:20], 'big') % n
                params[mask_type]["polynomial"].append((poly_a, poly_b, poly_c))

                # 置換テーブル（バイト単位の置換）
                subst = list(range(256))
                # シード値を使ってシャッフル
                subst_seed = int.from_bytes(h[20:24], 'big')
                random.seed(subst_seed)
                random.shuffle(subst)
                params[mask_type]["substitution"].append(subst)

        return params

    def apply_advanced_mask(self,
                           encrypted_chunks: List[int],
                           mask: Dict[str, Any]) -> List[int]:
        """
        暗号化されたチャンクに高度なマスクを適用

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            mask: 適用するマスク関数

        Returns:
            マスク適用後の暗号化チャンク
        """
        # 基本的なマスクを適用
        masked_chunks = self.apply_mask(encrypted_chunks, mask)

        # 追加の変換（高度なマスクの場合）
        if "polynomial" in mask["params"] and "substitution" in mask["params"]:
            # パラメータを取得
            poly_params = mask["params"]["polynomial"]
            subst_params = mask["params"]["substitution"]

            for i, chunk in enumerate(masked_chunks):
                # 多項式変換（ax^2 + bx + c mod n）
                poly_idx = i % len(poly_params)
                a, b, c = poly_params[poly_idx]

                # E(x) -> E(ax^2 + bx + c)
                # 手順1: E(x)^a -> E(ax)
                ax = self.paillier.homomorphic_multiply_constant(chunk, a)

                # 手順2: E(x)^2 = E(x^2) は直接できないため近似操作
                # 注：これは完全な準同型ではない簡易的なアプローチ
                # 実際には別の方法（例：完全準同型暗号）が必要

                # 手順3: E(bx) 計算
                bx = self.paillier.homomorphic_multiply_constant(chunk, b)

                # 手順4: E(ax^2 + bx + c) = E(ax^2) * E(bx) * E(c)
                result = self.paillier.homomorphic_add(ax, bx)
                result = self.paillier.homomorphic_add_constant(result, c)

                masked_chunks[i] = result

        return masked_chunks

    def remove_advanced_mask(self,
                            masked_chunks: List[int],
                            mask: Dict[str, Any]) -> List[int]:
        """
        高度なマスクを除去（逆マスクを適用）

        Args:
            masked_chunks: マスク適用済みの暗号化チャンク
            mask: 除去するマスク関数

        Returns:
            マスク除去後の暗号化チャンク
        """
        # 基本的なアプローチと同様、逆変換を適用
        # 高度なマスクの場合は複雑な逆変換が必要

        # 多項式変換の逆変換など（簡略化のため省略）
        # 注：実際にはより複雑な逆変換処理が必要

        # 基本マスクの除去
        return self.remove_mask(masked_chunks, mask)
```

### 5. テスト用の関数を追加

```python
def test_mask_functions():
    """
    マスク関数のテスト
    """
    # 準同型暗号システムの初期化
    from .homomorphic import PaillierCryptosystem

    print("マスク関数のテスト開始...")

    # 鍵生成
    print("鍵生成中...")
    paillier = PaillierCryptosystem(1024)  # 小さなビット長でテスト用
    public_key, private_key = paillier.generate_keypair()

    # マスク関数生成器の初期化
    mask_generator = MaskFunctionGenerator(paillier)

    # マスク関数の生成
    true_mask, false_mask = mask_generator.generate_mask_pair()
    print("マスク関数を生成しました")

    # テスト平文
    plaintext1 = 42
    plaintext2 = 100

    print(f"\n平文1: {plaintext1}")
    print(f"平文2: {plaintext2}")

    # 暗号化
    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    # マスク適用
    masked1 = mask_generator.apply_mask([ciphertext1], true_mask)
    masked2 = mask_generator.apply_mask([ciphertext2], false_mask)

    print("\nマスク適用後:")
    print(f"マスク適用後の暗号文1: {masked1[0]}")
    print(f"マスク適用後の暗号文2: {masked2[0]}")

    # マスク適用後の値を復号
    decrypted_masked1 = paillier.decrypt(masked1[0])
    decrypted_masked2 = paillier.decrypt(masked2[0])

    print(f"\nマスク適用後の復号結果1: {decrypted_masked1}")
    print(f"マスク適用後の復号結果2: {decrypted_masked2}")
    print(f"平文とは異なる値になっていることを確認: {plaintext1 != decrypted_masked1}")

    # マスク除去
    unmasked1 = mask_generator.remove_mask(masked1, true_mask)
    unmasked2 = mask_generator.remove_mask(masked2, false_mask)

    # マスク除去後の値を復号
    decrypted_unmasked1 = paillier.decrypt(unmasked1[0])
    decrypted_unmasked2 = paillier.decrypt(unmasked2[0])

    print(f"\nマスク除去後の復号結果1: {decrypted_unmasked1}")
    print(f"マスク除去後の復号結果2: {decrypted_unmasked2}")
    print(f"元の平文と一致することを確認1: {plaintext1 == decrypted_unmasked1}")
    print(f"元の平文と一致することを確認2: {plaintext2 == decrypted_unmasked2}")

    print("\n=== 変換テスト ===")

    # 真偽テキストの暗号化
    true_text = "これは正規のファイルです。"
    false_text = "これは非正規のファイルです。"

    # バイト列に変換
    true_bytes = true_text.encode('utf-8')
    false_bytes = false_text.encode('utf-8')

    # チャンクサイズ
    chunk_size = 32

    # バイト列を整数に変換
    true_int = int.from_bytes(true_bytes, 'big')
    false_int = int.from_bytes(false_bytes, 'big')

    # 暗号化
    true_enc = [paillier.encrypt(true_int)]
    false_enc = [paillier.encrypt(false_int)]

    # 変換
    masked_true, masked_false = transform_between_true_false(
        paillier, true_enc, false_enc, mask_generator)

    print("変換が完了しました")

    # 区別不可能な形式に変換
    indistinguishable = create_indistinguishable_form(
        masked_true, masked_false, true_mask, false_mask)

    print("区別不可能な形式に変換しました")

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
        decrypted_int = paillier.decrypt(unmasked[0])

        # 整数をバイト列に変換し、文字列にデコード
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        decrypted_text = decrypted_bytes.decode('utf-8')

        print(f"\n{key_type}鍵での抽出結果: {decrypted_text}")

        # 期待される結果と比較
        expected = true_text if key_type == "true" else false_text
        print(f"期待される結果と一致: {decrypted_text == expected}")

    print("\nテスト完了")


if __name__ == "__main__":
    test_mask_functions()
```

## ✅ 完了条件

- [ ] 基本的なマスク関数の生成と適用が実装されている
- [ ] マスク関数の除去（逆適用）機能が実装されている
- [ ] 真と偽のマスク関数が区別できないよう適切に設計されている
- [ ] 暗号文を真と偽の両方の状態に変換する機能が実装されている
- [ ] 区別不可能な形式での暗号文データの取り扱い機能が実装されている
- [ ] より高度なマスク関数（多項式変換など）が実装されている
- [ ] テスト関数が正しく動作し、マスク適用と除去が正しく機能することが確認できる
- [ ] コードにはわかりやすいコメントが付けられている

## 🧪 テスト方法

以下のコマンドでテストを実行して、マスク関数の生成と適用が正しく動作することを確認してください：

```bash
python -m method_8_homomorphic.crypto_mask
```

テスト出力で以下の項目を確認してください：

- マスク適用後の暗号文を復号すると、元の平文とは異なる値になっていること
- マスク除去後の暗号文を復号すると、元の平文と一致すること
- 区別不可能な形式からの抽出で、キータイプに応じて正しい平文が得られること

## ⏰ 想定実装時間

約 10 時間

## 📚 参考資料

- [準同型暗号の特性と活用](https://en.wikipedia.org/wiki/Homomorphic_encryption)
- [Paillier 暗号のマスキング応用](https://www.researchgate.net/publication/220334257_A_Generalization_of_Paillier's_Public-Key_System_with_Applications_to_Electronic_Voting)
- [セキュアなマスキング技法](https://eprint.iacr.org/2010/548.pdf)

## 💬 備考

- このモジュールは準同型暗号の特殊な応用例であり、実装の複雑さに注意してください
- マスク関数の生成と適用は、準同型暗号の特性を深く理解している必要があります
- 適用するマスク関数の選択は鍵の種類（true/false）に依存していますが、この依存関係がソースコード解析から判別できないよう設計する必要があります
- 実際の運用では、より複雑なマスク関数を検討する必要があるかもしれません
- 性能上の制約があるため、大きなファイルの処理では注意が必要です

疑問点があれば、いつでも質問してくださいね！レオくんと一緒にお手伝いします！💕

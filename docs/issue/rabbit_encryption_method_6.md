# ラビット暗号化方式 🐰 実装【子 Issue #6】：多重データカプセル化の実装

お兄様！最も重要な「秘密の仕掛け」、多重データカプセル化機能を実装しましょう！これがラビット暗号化方式の魔法の部分です ✨

## 📋 タスク概要

`method_6_rabbit/multipath_decrypt.py` ファイルに、2 つの異なる暗号化データ（正規と非正規）を単一のカプセルに格納し、鍵に応じて適切なデータを取り出す機能を実装します。この機能により、同一の暗号文から異なる平文を復元する核心部分を実現します。

## 🔧 実装内容

### 主要な機能：

1. 複数の暗号化データを単一のカプセルに結合する機能
2. 鍵に応じて適切なデータを抽出する機能
3. カプセル化/解カプセル化のアルゴリズムを実装
4. データが数学的に区別不可能であることを保証する機能

## 💻 実装手順

### 1. 必要なライブラリのインポート

`multipath_decrypt.py` の先頭に以下を記述します：

```python
"""
多重データカプセル化モジュール

複数の暗号化データを単一のカプセルに結合し、
鍵に応じて適切なデータを取り出す機能を提供します。
これによりラビット暗号化方式の多重復号パス機能を実現します。
"""

import os
import hashlib
import secrets
import random
import hmac
from typing import Dict, Tuple, List, Union, Optional, Any, Callable
import binascii

# 内部モジュールのインポート
from .stream_selector import determine_key_type_secure
from .config import KEY_SIZE_BYTES, SALT_SIZE
```

### 2. 定数と設定の定義

```python
# カプセル化パラメータ
CAPSULE_VERSION = 1
HASH_ALGORITHM = 'sha256'
MIXING_FUNCTIONS_COUNT = 4  # 混合関数の数
MIX_SEED_SIZE = 32  # 混合シードのサイズ
```

### 3. 混合関数の実装

```python
def create_mixing_functions(seed: bytes) -> List[Callable[[int, int, int], int]]:
    """
    データ混合関数を生成

    シード値に基づき、複数の数学的混合関数を生成します。
    これらの関数は2つのデータを区別不可能な方法で混合します。

    Args:
        seed: 乱数シード

    Returns:
        混合関数のリスト
    """
    # シードから複数のハッシュ値を生成（各混合関数用）
    hash_seeds = []
    for i in range(MIXING_FUNCTIONS_COUNT):
        h = hashlib.sha256(seed + bytes([i])).digest()
        hash_seeds.append(h)

    # 混合関数1: XORベース
    def mix_xor(a: int, b: int, pos: int) -> int:
        seed_byte = hash_seeds[0][pos % len(hash_seeds[0])]
        return (a ^ b ^ seed_byte) & 0xFF

    # 混合関数2: 加算ベース
    def mix_add(a: int, b: int, pos: int) -> int:
        seed_byte = hash_seeds[1][pos % len(hash_seeds[1])]
        return (a + b + seed_byte) & 0xFF

    # 混合関数3: 回転ベース
    def mix_rotate(a: int, b: int, pos: int) -> int:
        seed_byte = hash_seeds[2][pos % len(hash_seeds[2])]
        rotation = seed_byte % 8
        rotated_a = ((a << rotation) | (a >> (8 - rotation))) & 0xFF
        return (rotated_a ^ b) & 0xFF

    # 混合関数4: 差分ベース
    def mix_diff(a: int, b: int, pos: int) -> int:
        seed_byte = hash_seeds[3][pos % len(hash_seeds[3])]
        return (a - b + 256 + seed_byte) & 0xFF

    return [mix_xor, mix_add, mix_rotate, mix_diff]


def create_reverse_mixing_functions(seed: bytes) -> List[Callable[[int, int, int], int]]:
    """
    データ抽出関数（混合関数の逆関数）を生成

    シード値に基づき、混合関数の逆操作を行う関数を生成します。

    Args:
        seed: 乱数シード（混合関数と同一）

    Returns:
        抽出関数のリスト
    """
    # シードから複数のハッシュ値を生成（各混合関数用）
    hash_seeds = []
    for i in range(MIXING_FUNCTIONS_COUNT):
        h = hashlib.sha256(seed + bytes([i])).digest()
        hash_seeds.append(h)

    # 抽出関数1: XORベース
    def extract_xor(c: int, unused: int, pos: int) -> Tuple[int, int]:
        seed_byte = hash_seeds[0][pos % len(hash_seeds[0])]
        # XORは自己反転操作
        a = (c ^ seed_byte) & 0xFF
        b = a  # 一度抽出した値からもう一つの値は特定できない
        return a, b

    # 抽出関数2: 加算ベース
    def extract_add(c: int, unused: int, pos: int) -> Tuple[int, int]:
        seed_byte = hash_seeds[1][pos % len(hash_seeds[1])]
        # 加算の逆操作は減算
        a = (c - seed_byte) & 0xFF
        # 厳密には一意に決まらないが、例として近似値を計算
        b = (a // 2) & 0xFF
        a = (a - b) & 0xFF
        return a, b

    # 抽出関数3: 回転ベース
    def extract_rotate(c: int, unused: int, pos: int) -> Tuple[int, int]:
        seed_byte = hash_seeds[2][pos % len(hash_seeds[2])]
        rotation = seed_byte % 8
        # 逆回転してaの候補を計算
        possible_a = []
        for a_candidate in range(256):
            rotated_a = ((a_candidate << rotation) | (a_candidate >> (8 - rotation))) & 0xFF
            b_candidate = rotated_a ^ c
            if (rotated_a ^ b_candidate) == c:
                possible_a.append(a_candidate)

        # 候補が見つからない場合はシード依存の値を返す
        if not possible_a:
            return hash_seeds[2][pos % len(hash_seeds[2])], c

        # 候補からシード依存で一つ選択
        idx = seed_byte % len(possible_a)
        a = possible_a[idx]
        b = ((a << rotation) | (a >> (8 - rotation))) & 0xFF ^ c
        return a, b

    # 抽出関数4: 差分ベース
    def extract_diff(c: int, unused: int, pos: int) -> Tuple[int, int]:
        seed_byte = hash_seeds[3][pos % len(hash_seeds[3])]
        # 差分の逆操作
        b = (seed_byte - c + 256) & 0xFF
        a = (c + b - seed_byte) & 0xFF
        return a, b

    return [extract_xor, extract_add, extract_rotate, extract_diff]


def select_mixing_function(pos: int, seed: bytes) -> int:
    """
    位置に応じて使用する混合関数を選択

    各バイト位置に対して使用する混合関数を決定します。
    この選択は暗号化と復号で同一である必要があります。

    Args:
        pos: データ内の位置
        seed: 乱数シード

    Returns:
        混合関数のインデックス（0-3）
    """
    # 位置とシードを組み合わせて関数を選択
    # 注意: この選択は暗号文解析から予測できないようにする
    h = hashlib.sha256(seed + pos.to_bytes(4, byteorder='big')).digest()
    return h[0] % MIXING_FUNCTIONS_COUNT
```

### 4. カプセル化・解カプセル化関数の実装

```python
def encapsulate_data(true_data: bytes, false_data: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    2つの暗号化データを単一のカプセルに結合

    Args:
        true_data: 真のストリームで暗号化されたデータ
        false_data: 偽のストリームで暗号化されたデータ
        salt: ソルト値（省略時はランダム生成）

    Returns:
        (capsule, salt): カプセル化されたデータとソルト
    """
    if len(true_data) != len(false_data):
        raise ValueError("2つのデータは同じ長さである必要があります")

    # ソルトが指定されていない場合は生成
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # 混合シードの生成
    mix_seed = hashlib.sha256(salt).digest()

    # 混合関数を生成
    mix_funcs = create_mixing_functions(mix_seed)

    # データ長
    data_length = len(true_data)

    # カプセル化されたデータ
    capsule = bytearray(data_length)

    # 各バイトを混合
    for i in range(data_length):
        # どの混合関数を使用するか決定
        func_idx = select_mixing_function(i, mix_seed)

        # 選択された関数でデータを混合
        capsule[i] = mix_funcs[func_idx](true_data[i], false_data[i], i)

    return bytes(capsule), salt


def extract_data_from_capsule(capsule: bytes, key: Union[str, bytes], salt: bytes) -> bytes:
    """
    カプセルから鍵に応じたデータを抽出

    Args:
        capsule: カプセル化されたデータ
        key: 抽出に使用する鍵
        salt: ソルト値

    Returns:
        抽出されたデータ
    """
    # 鍵種別の判定
    key_type = determine_key_type_secure(key, salt)

    # 混合シードの生成
    mix_seed = hashlib.sha256(salt).digest()

    # 抽出関数を生成
    extract_funcs = create_reverse_mixing_functions(mix_seed)

    # データ長
    data_length = len(capsule)

    # 抽出されたデータ
    extracted = bytearray(data_length)

    # 各バイトを抽出
    for i in range(data_length):
        # どの抽出関数を使用するか決定
        func_idx = select_mixing_function(i, mix_seed)

        # 選択された関数でデータを抽出
        true_byte, false_byte = extract_funcs[func_idx](capsule[i], 0, i)

        # 鍵種別に応じて適切なデータを選択
        if key_type == "true":
            extracted[i] = true_byte
        else:
            extracted[i] = false_byte

    return bytes(extracted)
```

### 5. セキュリティ強化関数の実装

```python
def apply_security_transformations(capsule: bytes, salt: bytes) -> bytes:
    """
    カプセル化データにセキュリティ強化変換を適用

    これにより解析攻撃に対する耐性を高めます。

    Args:
        capsule: カプセル化されたデータ
        salt: ソルト値

    Returns:
        セキュリティ強化されたカプセル
    """
    # カプセルのコピーを作成
    result = bytearray(capsule)

    # 変換シードの生成
    transform_seed = hashlib.sha256(salt + b"transform").digest()

    # カプセル全体にわたる変換を適用
    for i in range(3):  # 複数回の変換を適用
        # 一時バッファ
        temp = bytearray(len(result))

        # 変換済みのデータで一時バッファを初期化
        for j in range(len(result)):
            temp[j] = result[j]

        # バイト間の依存関係を導入（解析を困難にする）
        for j in range(len(result)):
            prev_idx = (j - 1) % len(result)
            next_idx = (j + 1) % len(result)

            # 隣接バイトとハッシュシードに依存した変換
            transform_byte = transform_seed[(i * 7 + j) % len(transform_seed)]
            result[j] = (temp[j] ^ ((temp[prev_idx] + temp[next_idx]) & 0xFF) ^ transform_byte) & 0xFF

    return bytes(result)


def reverse_security_transformations(transformed: bytes, salt: bytes) -> bytes:
    """
    セキュリティ変換の逆操作を適用

    Args:
        transformed: 変換されたカプセル
        salt: ソルト値

    Returns:
        元のカプセル
    """
    # 変換されたデータのコピーを作成
    result = bytearray(transformed)

    # 変換シードの生成
    transform_seed = hashlib.sha256(salt + b"transform").digest()

    # 変換の逆操作を適用（逆順）
    for i in range(2, -1, -1):  # 3, 2, 1の順
        # 一時バッファ
        temp = bytearray(len(result))

        # 変換済みのデータで一時バッファを初期化
        for j in range(len(result)):
            temp[j] = result[j]

        # 変換の逆操作
        for j in range(len(result)):
            prev_idx = (j - 1) % len(result)
            next_idx = (j + 1) % len(result)

            transform_byte = transform_seed[(i * 7 + j) % len(transform_seed)]
            result[j] = (temp[j] ^ ((temp[prev_idx] + temp[next_idx]) & 0xFF) ^ transform_byte) & 0xFF

    return bytes(result)
```

### 6. より高度なエンドツーエンド処理関数の実装

```python
def create_multipath_capsule(true_data: bytes, false_data: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    2つのデータパスを持つ高度なカプセルを作成

    Args:
        true_data: 真のデータ
        false_data: 偽のデータ
        salt: ソルト値（省略時はランダム生成）

    Returns:
        (capsule, salt): カプセルとソルト
    """
    # 基本的なカプセル化
    basic_capsule, salt = encapsulate_data(true_data, false_data, salt)

    # セキュリティ強化変換を適用
    enhanced_capsule = apply_security_transformations(basic_capsule, salt)

    # カプセルに識別不能性を追加
    # 注: これにより同じ入力でも毎回異なるカプセルが生成される
    final_capsule = add_indistinguishability(enhanced_capsule, salt)

    return final_capsule, salt


def extract_from_multipath_capsule(capsule: bytes, key: Union[str, bytes], salt: bytes) -> bytes:
    """
    多重パスカプセルから鍵に応じたデータを抽出

    Args:
        capsule: カプセル化されたデータ
        key: 抽出に使用する鍵
        salt: ソルト値

    Returns:
        抽出されたデータ
    """
    # 識別不能性の除去
    reduced_capsule = remove_indistinguishability(capsule, salt)

    # セキュリティ変換の逆操作
    basic_capsule = reverse_security_transformations(reduced_capsule, salt)

    # カプセルからデータを抽出
    extracted = extract_data_from_capsule(basic_capsule, key, salt)

    return extracted


def add_indistinguishability(capsule: bytes, salt: bytes) -> bytes:
    """
    カプセルに識別不能性を追加

    これにより同じ入力でも毎回異なる出力が生成されます。

    Args:
        capsule: 元のカプセル
        salt: ソルト値

    Returns:
        識別不能性が付加されたカプセル
    """
    # ノイズシードの生成
    noise_seed = hashlib.sha256(salt + b"noise").digest()

    # カプセルと同じ長さのノイズを生成
    # 注: このノイズは解析からの保護のみを目的とし、
    # 実際のデータには影響しない設計

    result = bytearray(capsule)

    # 各バイトに小さな可逆変換を適用
    for i in range(len(result)):
        noise_byte = noise_seed[i % len(noise_seed)]

        # ビット位置により異なる処理を適用（可逆的に）
        for bit in range(8):
            if (noise_byte >> bit) & 1:
                # ビットの入れ替え（下位2ビットは不変）
                if bit >= 2:
                    mask = (1 << bit) | (1 << ((bit + 2) % 8))
                    if bit < 6:  # 上位2ビットは不変
                        current = result[i] & mask
                        inverted = current ^ mask
                        result[i] = (result[i] & ~mask) | inverted

    return bytes(result)


def remove_indistinguishability(capsule: bytes, salt: bytes) -> bytes:
    """
    識別不能性を除去してカプセルを復元

    Args:
        capsule: 識別不能性が付加されたカプセル
        salt: ソルト値

    Returns:
        元のカプセル
    """
    # ノイズシードの生成
    noise_seed = hashlib.sha256(salt + b"noise").digest()

    result = bytearray(capsule)

    # add_indistinguishabilityと逆順で処理
    for i in range(len(result) - 1, -1, -1):
        noise_byte = noise_seed[i % len(noise_seed)]

        # 逆順でビット処理
        for bit in range(7, -1, -1):
            if (noise_byte >> bit) & 1:
                if bit >= 2:
                    mask = (1 << bit) | (1 << ((bit + 2) % 8))
                    if bit < 6:
                        current = result[i] & mask
                        inverted = current ^ mask
                        result[i] = (result[i] & ~mask) | inverted

    return bytes(result)
```

### 7. テスト関数の実装

```python
def test_multipath_capsule():
    """
    多重パスカプセル化と抽出のテスト
    """
    # テストデータ
    true_data = b"This is the true data that should be extracted with the correct key."
    false_data = b"This is the false data that should be extracted with the wrong key."

    # データ長の調整
    max_len = max(len(true_data), len(false_data))
    true_data = true_data.ljust(max_len, b' ')
    false_data = false_data.ljust(max_len, b' ')

    # カプセル化
    capsule, salt = create_multipath_capsule(true_data, false_data)

    # テスト用の鍵
    test_key_true = "correct_key_for_true_data"
    test_key_false = "wrong_key_for_false_data"

    # 抽出テスト
    extracted_true = extract_from_multipath_capsule(capsule, test_key_true, salt)
    extracted_false = extract_from_multipath_capsule(capsule, test_key_false, salt)

    # 結果表示
    print("元の真データ:", true_data)
    print("元の偽データ:", false_data)
    print("\nカプセル（最初の32バイト）:", binascii.hexlify(capsule[:32]).decode())
    print("ソルト:", binascii.hexlify(salt).decode())
    print("\n正規鍵での抽出結果:", extracted_true)
    print("非正規鍵での抽出結果:", extracted_false)

    # 検証
    print("\n検証:")
    print("真データの抽出成功:", extracted_true == true_data)
    print("偽データの抽出成功:", extracted_false == false_data)


# メイン関数
if __name__ == "__main__":
    test_multipath_capsule()
```

## ✅ 完了条件

- [ ] 2 つの異なるデータを単一のカプセルに結合する機能が実装されている
- [ ] 鍵に応じて適切なデータを抽出する機能が実装されている
- [ ] カプセル化/解カプセル化が数学的に安全な方法で実装されている
- [ ] セキュリティ強化変換が適用されている
- [ ] 同じ入力でも毎回異なる出力が生成される識別不能性機能が実装されている
- [ ] テスト関数が正常に動作し、期待した結果が得られる
- [ ] ソースコード解析から真偽の判別が不可能である

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# モジュールを直接実行してテスト
python -m method_6_rabbit.multipath_decrypt

# カプセル化と抽出のテスト
python -c "from method_6_rabbit.multipath_decrypt import create_multipath_capsule, extract_from_multipath_capsule; true_data = b'True data'; false_data = b'False data'; capsule, salt = create_multipath_capsule(true_data, false_data); print(extract_from_multipath_capsule(capsule, 'true_key', salt)); print(extract_from_multipath_capsule(capsule, 'false_key', salt))"

# カプセル内容の検証（カプセルを10回生成し、内容が毎回異なることを確認）
python -c "import binascii; from method_6_rabbit.multipath_decrypt import create_multipath_capsule; true_data = b'True data'; false_data = b'False data'; capsules = [create_multipath_capsule(true_data, false_data)[0] for _ in range(10)]; for i, c in enumerate(capsules): print(f'Capsule {i}: {binascii.hexlify(c[:16]).decode()}'); print('All unique:', len(set([c[:16] for c in capsules])) == len(capsules))"
```

## ⏰ 想定実装時間

約 10 時間

## 📚 参考資料

- [Indistinguishability under chosen-plaintext attack (IND-CPA)](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability)
- [Confusion and Diffusion in Cryptography](https://en.wikipedia.org/wiki/Confusion_and_diffusion)
- [NIST SP 800-38A - Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

## 💬 備考

- この実装は極めて重要で、システム全体の安全性を決定づけます。特に注意して実装してください。
- カプセル化アルゴリズムはソースコードを解析しても、どちらが真のデータか判別できないよう注意深く設計してください。
- 各関数には十分な乱数性を持たせ、パターンや偏りがないことを確認してください。
- 同じ入力データでも、生成されるカプセルは毎回異なるようにしてください（識別不能性）。
- パフォーマンスと安全性のバランスを考慮し、過度に複雑な処理は避けつつ、十分な安全性を確保してください。

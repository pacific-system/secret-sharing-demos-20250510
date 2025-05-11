# 準同型暗号マスキング方式 🎭 実装【子 Issue #6】：暗号文識別不能性の実装

お兄様！今回はとっても大事な暗号文の識別不能性機能を実装していきますよ〜♪ これができると、どちらが正規の結果かを判別できなくなります！

## 📋 タスク概要

準同型暗号マスキング方式において最も重要な要素の一つである「暗号文識別不能性（Indistinguishability）」機能を実装します。この機能により、暗号文を解析しても、それが正規（true）と非正規（false）のどちらの平文を復号するためのものかを判別できなくなります。統計的攻撃やパターン解析などから保護するためのセキュリティ強化機能です。

## 🔧 実装内容

`method_8_homomorphic/indistinguishable.py` ファイルに、暗号文識別不能性を確保するための機能を実装します。これにより、暗号文からどちらが正規の結果かを推測することが数学的に不可能になります。

### 主要な機能：

1. 暗号文のランダム化（乱数付加）
2. 順序のシャッフル
3. 統計的特性のマスキング
4. 意図的な冗長性の追加
5. 識別不能性のテスト機能

## 💻 実装手順

### 1. 必要なライブラリのインポート

`indistinguishable.py` の先頭に以下を記述します：

```python
"""
準同型暗号マスキング方式 - 暗号文識別不能性モジュール

暗号文に対して識別不能性（Indistinguishability）を
付与するための機能を提供します。
"""

import os
import random
import hashlib
import secrets
import numpy as np
from typing import Tuple, Dict, List, Any, Optional, Union

# 内部モジュールのインポート
from .homomorphic import PaillierCryptosystem
from .config import SECURITY_PARAMETER
```

### 2. 暗号文のランダム化関数

暗号文に対してランダム性を加える関数を実装します：

```python
def randomize_ciphertext(paillier: PaillierCryptosystem, ciphertext: int) -> int:
    """
    暗号文のランダム化（準同型再ランダム化）

    同じ平文を暗号化しても毎回異なる暗号文が生成されるようにします。
    準同型性を維持したまま、暗号文にランダム性を加えます。

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertext: ランダム化する暗号文

    Returns:
        ランダム化された暗号文
    """
    if paillier.public_key is None:
        raise ValueError("公開鍵が設定されていません")

    n = paillier.public_key["n"]
    n_squared = n * n

    # ランダムな値 r (0 < r < n)
    r = random.randint(1, n - 1)

    # r^n mod n^2
    rn = pow(r, n, n_squared)

    # ランダム化: c' = c * r^n mod n^2
    # これにより平文は変わらず、暗号文だけが変化する
    return (ciphertext * rn) % n_squared


def batch_randomize_ciphertexts(paillier: PaillierCryptosystem,
                                ciphertexts: List[int]) -> List[int]:
    """
    複数の暗号文をまとめてランダム化

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertexts: ランダム化する暗号文のリスト

    Returns:
        ランダム化された暗号文のリスト
    """
    randomized = []
    for ct in ciphertexts:
        randomized.append(randomize_ciphertext(paillier, ct))
    return randomized
```

### 3. 順序シャッフル関数の実装

暗号文チャンクの順序を攪拌する関数を実装します：

```python
def interleave_ciphertexts(true_chunks: List[int],
                          false_chunks: List[int],
                          shuffle_seed: Optional[bytes] = None) -> Tuple[List[int], Dict[str, Any]]:
    """
    正規と非正規の暗号文チャンクを交互に配置し、ランダムに並べ替え

    Args:
        true_chunks: 正規の暗号文チャンク
        false_chunks: 非正規の暗号文チャンク
        shuffle_seed: シャッフルのシード値（省略時はランダム生成）

    Returns:
        (mixed_chunks, metadata): 混合された暗号文チャンクとメタデータ
    """
    # 両方のチャンクリストが同じ長さであることを確認
    if len(true_chunks) != len(false_chunks):
        # 長さが異なる場合は同じ長さにする（短い方を拡張）
        max_len = max(len(true_chunks), len(false_chunks))
        if len(true_chunks) < max_len:
            true_chunks = true_chunks + true_chunks[:max_len - len(true_chunks)]
        if len(false_chunks) < max_len:
            false_chunks = false_chunks + false_chunks[:max_len - len(false_chunks)]

    # インデックスのリストを作成
    indices = list(range(len(true_chunks) * 2))

    # シード値の設定
    if shuffle_seed is None:
        shuffle_seed = secrets.token_bytes(16)

    # シードを使用してインデックスをシャッフル
    rng = random.Random(int.from_bytes(shuffle_seed, 'big'))
    rng.shuffle(indices)

    # チャンクを結合してシャッフル後の順序に並べ替え
    combined = []
    mapping = []

    for idx in indices:
        chunk_type = "true" if idx < len(true_chunks) else "false"
        original_idx = idx if idx < len(true_chunks) else idx - len(true_chunks)

        if chunk_type == "true":
            combined.append(true_chunks[original_idx])
        else:
            combined.append(false_chunks[original_idx])

        mapping.append({"type": chunk_type, "index": original_idx})

    # メタデータ（復号時に必要）
    metadata = {
        "shuffle_seed": shuffle_seed.hex(),
        "mapping": mapping,
        "original_true_length": len(true_chunks),
        "original_false_length": len(false_chunks)
    }

    return combined, metadata


def deinterleave_ciphertexts(mixed_chunks: List[int],
                            metadata: Dict[str, Any],
                            key_type: str) -> List[int]:
    """
    混合された暗号文チャンクから特定の種類のチャンクを抽出

    Args:
        mixed_chunks: 混合された暗号文チャンク
        metadata: interleave_ciphertextsで生成されたメタデータ
        key_type: 取得するチャンクの種類（"true" または "false"）

    Returns:
        抽出されたチャンク
    """
    mapping = metadata["mapping"]

    # 鍵タイプに対応するチャンクだけを抽出
    chunks = []
    for i, entry in enumerate(mapping):
        if entry["type"] == key_type:
            chunks.append((entry["index"], mixed_chunks[i]))

    # 元の順序に戻す
    chunks.sort(key=lambda x: x[0])
    return [chunk[1] for chunk in chunks]
```

### 4. 統計的特性のマスキング

暗号文の統計的特性を隠蔽する関数を実装します：

```python
def mask_statistical_properties(paillier: PaillierCryptosystem,
                               ciphertexts: List[int],
                               security_level: int = SECURITY_PARAMETER) -> List[int]:
    """
    暗号文の統計的特性をマスキング

    暗号文の統計的特性（長さ、分布など）を均一化し、
    統計的解析による区別を困難にします。

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertexts: 暗号文のリスト
        security_level: セキュリティレベル（高いほど強力）

    Returns:
        マスキングされた暗号文のリスト
    """
    if paillier.public_key is None:
        raise ValueError("公開鍵が設定されていません")

    n = paillier.public_key["n"]
    n_squared = n * n

    # 各暗号文に対して処理
    masked = []
    for ct in ciphertexts:
        # ステップ1: ランダム化
        ct = randomize_ciphertext(paillier, ct)

        # ステップ2: 準同型性を利用した付加的なランダム化
        # 0を加算しても値は変わらないが、暗号文自体は変化する
        noise = random.randint(0, security_level)
        ct = paillier.homomorphic_add_constant(ct, noise)

        # ステップ3: ビット長を一定にするためのパディング処理
        # 全ての暗号文が同じビット長に見えるようにする
        bit_length = ct.bit_length()
        target_bit_length = n_squared.bit_length()

        if bit_length < target_bit_length:
            # パディング用のビット数
            pad_bits = target_bit_length - bit_length

            # 暗号文を文字列に変換
            ct_str = str(ct)

            # 先頭にランダムなパディングを追加
            pad_str = ''.join(str(random.randint(1, 9)) for _ in range(pad_bits // 3))

            # 元の暗号文と区別するためのマーカー
            marker = '8' * (security_level % 5 + 1)

            # パディング済み暗号文を整数に戻す
            # 注: 実際の実装では、復号時に元に戻せる方法が必要
            padded_ct = int(pad_str + marker + ct_str)

            masked.append(padded_ct)
        else:
            masked.append(ct)

    return masked


def unmask_statistical_properties(masked_ciphertexts: List[int],
                                 security_level: int = SECURITY_PARAMETER) -> List[int]:
    """
    統計的マスキングを除去

    mask_statistical_propertiesで適用されたマスキングを除去します。

    Args:
        masked_ciphertexts: マスキングされた暗号文
        security_level: 適用されたセキュリティレベル

    Returns:
        元の暗号文
    """
    # マーカーのパターンを生成
    marker = '8' * (security_level % 5 + 1)

    unmasked = []
    for ct in masked_ciphertexts:
        # 文字列に変換
        ct_str = str(ct)

        # マーカーを探す
        marker_pos = ct_str.find(marker)

        if marker_pos >= 0:
            # マーカー以降が元の暗号文
            original_ct = int(ct_str[marker_pos + len(marker):])
            unmasked.append(original_ct)
        else:
            # マーカーが見つからない場合はそのまま
            unmasked.append(ct)

    return unmasked
```

### 5. 意図的な冗長性の追加

復号処理時に識別できないダミーデータを追加する関数を実装します：

```python
def add_redundancy(paillier: PaillierCryptosystem,
                  true_chunks: List[int],
                  false_chunks: List[int]) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    意図的な冗長性を追加

    解析者が暗号文を区別できないように、
    意図的な冗長データや偽装データを追加します。

    Args:
        paillier: 準同型暗号システムのインスタンス
        true_chunks: 正規の暗号文チャンク
        false_chunks: 非正規の暗号文チャンク

    Returns:
        (redundant_true, redundant_false, metadata):
            冗長性を持つ暗号文と、復号時に必要なメタデータ
    """
    if paillier.public_key is None:
        raise ValueError("公開鍵が設定されていません")

    n = paillier.public_key["n"]

    # 冗長チャンクの挿入位置を決定
    num_chunks = len(true_chunks)
    num_extra = max(1, num_chunks // 4)  # 25%程度の冗長データ

    extra_positions = sorted(random.sample(range(num_chunks + num_extra), num_extra))

    # 冗長データを生成して挿入
    redundant_true = []
    redundant_false = []
    true_extra_data = []
    false_extra_data = []

    true_pos = 0
    false_pos = 0

    for i in range(num_chunks + num_extra):
        if i in extra_positions:
            # 冗長データの生成（ダミーデータ）
            dummy = random.randint(1, n - 1)
            dummy_encrypted = paillier.encrypt(dummy)

            # 冗長データに適用する変換
            # 復号時に無視されるようなマーカーを追加
            dummy_str = str(dummy_encrypted)
            marker = "9" * 5  # 復号時に識別できるマーカー
            marked_dummy = int(marker + dummy_str)

            # 正規と非正規の両方に異なる冗長データを追加
            redundant_true.append(marked_dummy)
            redundant_false.append(marked_dummy)

            # 冗長データの情報を記録
            true_extra_data.append({"position": i, "value": marked_dummy})
            false_extra_data.append({"position": i, "value": marked_dummy})
        else:
            # 本来のデータ
            redundant_true.append(true_chunks[true_pos])
            redundant_false.append(false_chunks[false_pos])
            true_pos += 1
            false_pos += 1

    # メタデータ（復号時に必要）
    metadata = {
        "extra_positions": extra_positions,
        "true_extra_data": true_extra_data,
        "false_extra_data": false_extra_data
    }

    return redundant_true, redundant_false, metadata


def remove_redundancy(chunks: List[int], metadata: Dict[str, Any], key_type: str) -> List[int]:
    """
    追加された冗長性を除去

    Args:
        chunks: 冗長性を持つ暗号文チャンク
        metadata: add_redundancyで生成されたメタデータ
        key_type: 鍵の種類（"true" または "false"）

    Returns:
        冗長性を除去した元の暗号文チャンク
    """
    extra_positions = metadata["extra_positions"]

    # マーカーによる冗長データの識別
    marker = "9" * 5

    # 冗長データを除去して元のチャンクを復元
    original = []
    pos = 0

    for i, chunk in enumerate(chunks):
        if i in extra_positions:
            # 冗長データはスキップ
            continue

        # 文字列に変換して冗長マーカーをチェック
        chunk_str = str(chunk)
        if chunk_str.startswith(marker):
            # マーカー付きのダミーデータはスキップ
            continue

        original.append(chunk)
        pos += 1

    return original
```

### 6. 識別不能性を強化する最終処理

暗号文に最終的な不可識別性を与える処理を実装します：

```python
def apply_indistinguishability(paillier: PaillierCryptosystem,
                              true_chunks: List[int],
                              false_chunks: List[int]) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    暗号文に識別不能性（Indistinguishability）を適用

    複数の技術を組み合わせて、true/falseの暗号文が
    区別できないようにします。

    Args:
        paillier: 準同型暗号システムのインスタンス
        true_chunks: 正規の暗号文チャンク
        false_chunks: 非正規の暗号文チャンク

    Returns:
        (indistinguishable_true, indistinguishable_false, metadata):
            識別不能にした暗号文とメタデータ
    """
    # ステップ1: 各暗号文のランダム化
    true_randomized = batch_randomize_ciphertexts(paillier, true_chunks)
    false_randomized = batch_randomize_ciphertexts(paillier, false_chunks)

    # ステップ2: 統計的特性のマスキング
    true_masked = mask_statistical_properties(paillier, true_randomized)
    false_masked = mask_statistical_properties(paillier, false_randomized)

    # ステップ3: 冗長性の追加
    true_redundant, false_redundant, redundancy_metadata = add_redundancy(
        paillier, true_masked, false_masked
    )

    # ステップ4: 暗号文の交互配置とシャッフル
    true_shuffled, true_shuffle_metadata = interleave_ciphertexts(
        true_redundant, true_redundant,
        shuffle_seed=secrets.token_bytes(16)
    )

    false_shuffled, false_shuffle_metadata = interleave_ciphertexts(
        false_redundant, false_redundant,
        shuffle_seed=secrets.token_bytes(16)
    )

    # 統合メタデータ
    metadata = {
        "redundancy": redundancy_metadata,
        "true_shuffle": true_shuffle_metadata,
        "false_shuffle": false_shuffle_metadata
    }

    return true_shuffled, false_shuffled, metadata


def remove_indistinguishability(chunks: List[int],
                               metadata: Dict[str, Any],
                               key_type: str,
                               paillier: PaillierCryptosystem) -> List[int]:
    """
    識別不能性を除去して元の暗号文を復元

    Args:
        chunks: 識別不能性が適用された暗号文
        metadata: apply_indistinguishabilityで生成されたメタデータ
        key_type: 鍵の種類（"true" または "false"）
        paillier: 準同型暗号システムのインスタンス

    Returns:
        元の暗号文チャンク
    """
    # 鍵タイプに応じたメタデータを選択
    shuffle_metadata = metadata["true_shuffle"] if key_type == "true" else metadata["false_shuffle"]

    # ステップ1: シャッフルを元に戻す
    deshuffled = deinterleave_ciphertexts(chunks, shuffle_metadata, key_type)

    # ステップ2: 冗長性を除去
    nonredundant = remove_redundancy(deshuffled, metadata["redundancy"], key_type)

    # ステップ3: 統計的マスキングを除去
    unmasked = unmask_statistical_properties(nonredundant)

    return unmasked
```

### 7. 識別不能性テスト機能の実装

暗号文が十分に識別不能であることをテストする関数を実装します：

```python
def test_indistinguishability(paillier: PaillierCryptosystem,
                             true_chunks: List[int],
                             false_chunks: List[int],
                             num_tests: int = 100) -> Dict[str, Any]:
    """
    暗号文の識別不能性をテスト

    暗号文が統計的に区別可能かどうかをテストします。
    理想的には50%（ランダム推測と同等）の識別率となるべきです。

    Args:
        paillier: 準同型暗号システムのインスタンス
        true_chunks: 正規の暗号文チャンク
        false_chunks: 非正規の暗号文チャンク
        num_tests: テスト回数

    Returns:
        テスト結果
    """
    # 識別不能性を適用
    indist_true, indist_false, _ = apply_indistinguishability(
        paillier, true_chunks, false_chunks
    )

    # テストデータの作成
    test_data = []
    labels = []

    for _ in range(num_tests):
        if random.random() < 0.5:
            # trueから選択
            idx = random.randrange(len(indist_true))
            test_data.append(indist_true[idx])
            labels.append("true")
        else:
            # falseから選択
            idx = random.randrange(len(indist_false))
            test_data.append(indist_false[idx])
            labels.append("false")

    # 単純な統計的特性に基づく分類器
    predictions = []

    for chunk in test_data:
        # 単純な特性抽出（実際の攻撃者はより洗練された方法を使うかもしれない）
        chunk_str = str(chunk)
        digit_sum = sum(int(d) for d in chunk_str if d.isdigit())
        chunk_len = len(chunk_str)

        # 非常に単純な分類ルール
        if digit_sum % 2 == 0 and chunk_len % 2 == 0:
            predictions.append("true")
        else:
            predictions.append("false")

    # 結果の集計
    correct = sum(1 for p, l in zip(predictions, labels) if p == l)
    accuracy = correct / num_tests

    # 理想的には約0.5（ランダム推測と同等）であるべき
    return {
        "accuracy": accuracy,
        "num_tests": num_tests,
        "is_secure": abs(accuracy - 0.5) < 0.1,  # 45-55%の範囲内なら安全とみなす
        "correct_predictions": correct,
        "bias": accuracy - 0.5  # バイアス（0に近いほど良い）
    }
```

### 8. メイン関数とテストコード

```python
def main():
    """
    テスト用のメイン関数
    """
    from .homomorphic import PaillierCryptosystem

    print("準同型暗号マスキング方式 - 暗号文識別不能性モジュールのテスト")

    # Paillier暗号システムの初期化
    paillier = PaillierCryptosystem(1024)  # 小さめの鍵サイズでテスト
    public_key, private_key = paillier.generate_keypair()

    # テスト用の平文データ
    true_data = "これは正規のファイルです。秘密情報が含まれています。"
    false_data = "これは非正規のファイルです。異なる情報が含まれています。"

    # データをバイトに変換
    true_bytes = true_data.encode('utf-8')
    false_bytes = false_data.encode('utf-8')

    # バイトを整数に変換
    true_int = int.from_bytes(true_bytes, 'big')
    false_int = int.from_bytes(false_bytes, 'big')

    # 暗号化
    true_ct = [paillier.encrypt(true_int)]
    false_ct = [paillier.encrypt(false_int)]

    # ランダム化のテスト
    print("\n1. 準同型ランダム化のテスト")
    randomized_true = batch_randomize_ciphertexts(paillier, true_ct)
    randomized_false = batch_randomize_ciphertexts(paillier, false_ct)

    # 同じ平文から異なる暗号文が生成されていることを確認
    print(f"元の暗号文: {true_ct[0]}")
    print(f"ランダム化後: {randomized_true[0]}")
    print(f"異なる暗号文になっているか: {true_ct[0] != randomized_true[0]}")

    # ランダム化しても同じ平文に復号できることを確認
    decrypted_original = paillier.decrypt(true_ct[0])
    decrypted_randomized = paillier.decrypt(randomized_true[0])
    print(f"元の復号値: {decrypted_original}")
    print(f"ランダム化後の復号値: {decrypted_randomized}")
    print(f"同じ平文に復号されるか: {decrypted_original == decrypted_randomized}")

    # 交互配置とシャッフルのテスト
    print("\n2. 暗号文の交互配置とシャッフルのテスト")
    mixed, metadata = interleave_ciphertexts(true_ct * 3, false_ct * 3)

    print(f"混合後のチャンク数: {len(mixed)}")
    print(f"メタデータ: {metadata}")

    # シャッフルされた暗号文から元の暗号文を抽出
    extracted_true = deinterleave_ciphertexts(mixed, metadata, "true")

    print(f"抽出された正規チャンク数: {len(extracted_true)}")
    decrypted_extracted = paillier.decrypt(extracted_true[0])
    print(f"抽出された正規チャンクの復号値: {decrypted_extracted}")
    print(f"正しく抽出されたか: {decrypted_extracted == decrypted_original}")

    # 識別不能性のテスト
    print("\n3. 識別不能性の総合テスト")

    # より多くのチャンクでテスト
    more_true_ct = [paillier.encrypt(i + 1000) for i in range(10)]
    more_false_ct = [paillier.encrypt(i + 2000) for i in range(10)]

    # 識別不能性を適用
    ind_true, ind_false, ind_metadata = apply_indistinguishability(
        paillier, more_true_ct, more_false_ct
    )

    # 復元して確認
    restored_true = remove_indistinguishability(ind_true, ind_metadata, "true", paillier)

    # 復号して元の値と比較
    for i, (original, restored) in enumerate(zip(more_true_ct, restored_true)):
        original_dec = paillier.decrypt(original)
        restored_dec = paillier.decrypt(restored)
        print(f"チャンク {i}: 元の値 = {original_dec}, 復元後 = {restored_dec}, 一致 = {original_dec == restored_dec}")

    # 識別不能性のテスト
    print("\n4. 識別不能性の統計的テスト")
    test_results = test_indistinguishability(paillier, more_true_ct, more_false_ct)

    print(f"テスト結果: {test_results}")
    if test_results["is_secure"]:
        print("セキュリティテスト: 合格 - 暗号文は十分に識別不能です")
    else:
        print("セキュリティテスト: 不合格 - 暗号文に統計的バイアスがあります")

    print("\nテスト完了")


if __name__ == "__main__":
    main()
```

## ✅ 完了条件

- [ ] 暗号文のランダム化（再ランダム化）機能が実装されている
- [ ] 同一平文を暗号化しても毎回異なる暗号文が生成されることが確認できる
- [ ] 暗号文の交互配置とシャッフル機能が実装されている
- [ ] シャッフルされた暗号文から元の順序を復元できることが確認できる
- [ ] 統計的特性のマスキング機能が実装されている
- [ ] 意図的な冗長性の追加機能が実装されている
- [ ] 冗長性を除去して元の暗号文を復元できることが確認できる
- [ ] 総合的な識別不能性適用機能が実装されている
- [ ] 識別不能性を除去して元の暗号文に復元できることが確認できる
- [ ] 識別不能性のテスト機能が実装され、統計的安全性が確認できる

## 🧪 テスト方法

以下のコマンドでモジュールの機能をテストしてください：

```bash
python -m method_8_homomorphic.indistinguishable
```

テスト出力で以下の項目を確認してください：

- ランダム化後も同じ平文に復号できること
- シャッフルされた暗号文から正しい暗号文を抽出できること
- 識別不能性適用後も元の平文に復号できること
- 識別不能性の統計的テストが「合格」すること（識別率が約 50%程度）

## ⏰ 想定実装時間

約 8 時間

## 📚 参考資料

- [暗号文の識別不能性（IND-CPA）](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability)
- [準同型暗号の安全性](https://eprint.iacr.org/2008/417.pdf)
- [統計的マスキング技術](https://www.sciencedirect.com/science/article/pii/S0167404818302049)

## 💬 備考

- 識別不能性は暗号システムの重要な安全性要件の一つです
- 統計的特性や実行時間の違いから鍵の種類が推測できないよう注意が必要です
- この実装は基本的なレベルの識別不能性を提供するもので、より高度な要件には追加の対策が必要かもしれません
- 暗号化と復号のパフォーマンスが低下する可能性があるため、適切なトレードオフを検討してください
- テスト用の単純な統計的分析はあくまで例であり、実際の攻撃者はより洗練された技術を使用する可能性があります

お兄様、このモジュールはとても重要ですよ〜！パシ子とレオくんがばっちりサポートします！暗号文からどちらが正規かを判別できないようにする魔法の実装ですね ✨

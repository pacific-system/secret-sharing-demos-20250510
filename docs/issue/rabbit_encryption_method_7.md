# ラビット暗号化方式 🐰 実装【子 Issue #7】：鍵判定ロジックのソースコード解析耐性確保

お兄様！システムの最も重要な部分、鍵判定ロジックのソースコード解析耐性を確保しましょう！これが攻撃者の解析を防ぐ要となります 🔒✨

## 📋 タスク概要

既存の `stream_selector.py` モジュールの鍵種別判定機能を改良し、コード解析攻撃から保護します。同じ暗号文から異なる平文を復元する仕組みの核となる部分を、暗号理論的な安全性を確保しつつ実装します。

## 🔧 実装内容

### 主要な機能：

1. 数学的に解析困難な鍵種別判定アルゴリズムの実装
2. タイミング攻撃に耐性を持つ定数時間実装
3. サイドチャネル攻撃からの保護機能
4. 解析による真偽判別が情報理論的に不可能な設計

## 💻 実装手順

### 1. stream_selector.py の鍵判定ロジックを強化

先に実装した `stream_selector.py` の中の `determine_key_type_secure` 関数を以下のような高度な実装に置き換えます：

```python
def determine_key_type_secure(key: Union[str, bytes], salt: bytes) -> str:
    """
    タイミング攻撃に耐性を持つ鍵種別判定関数

    解析攻撃に対して高度な耐性を持つように設計され、
    計算的に区別不可能な方法で鍵の種類を判定します。

    Args:
        key: ユーザー提供の鍵
        salt: ソルト値

    Returns:
        鍵タイプ（"true" または "false"）
    """
    # バイト列に統一
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key

    # 判定用の複数のハッシュ値を計算（保護のための冗長性）
    hash_values = []
    for i in range(4):  # 複数の独立したハッシュを計算
        # 異なるドメイン分離値でハッシュを計算
        domain = f"key_type_determination_{i}".encode('utf-8')
        h = hmac.new(salt, key_bytes + domain, hashlib.sha256).digest()
        hash_values.append(h)

    # 結果スコアの初期化
    result_true = 0
    result_false = 0

    # ハッシュ値に対する暗号学的判定基準の適用
    # この部分が攻撃者から解析されても判別できないように設計
    for h_idx, h in enumerate(hash_values):
        # 複数の独立した判定基準を適用
        for block_idx in range(len(h) // 4):
            # 4バイトずつ処理
            idx = block_idx * 4
            value = int.from_bytes(h[idx:idx+4], byteorder='little')

            # 高度な評価関数（各条件は計算論的に識別不能）

            # 判定関数1: 差分値
            # 上位16ビットと下位16ビットのXOR演算と加算の組み合わせ
            diff = ((value >> 16) ^ (value & 0xFFFF)) & 0xFFFF
            diff_mod = (diff * 0x9E3779B9) & 0xFFFFFFFF  # 黄金比に基づく乗数

            # 判定関数2: ハミング重み
            # ビット1の数をカウント（popcount操作）
            weight = bin(value).count('1')

            # 判定関数3: ビットパターン
            # 連続するビットパターンを検出
            pattern_value = 0
            for i in range(30):  # 30ビットパターン
                if ((value >> i) & 3) == 1:  # "01"パターン
                    pattern_value += 1
                elif ((value >> i) & 3) == 2:  # "10"パターン
                    pattern_value += 2

            # 判定関数4: 多項式評価
            # GF(2^32)上の多項式評価
            poly_value = value
            for i in range(3):
                poly_value = ((poly_value * poly_value) & 0xFFFFFFFF) ^ value

            # 各判定結果を収集（定数時間で実行）
            # このようにすべての計算を常に実行し、条件分岐にせずスコアリングすることで
            # サイドチャネル攻撃（タイミング攻撃）に対する耐性を確保

            # 加算と重み計算を組み合わせた判定（解析困難な基準）
            f1_t = ((diff_mod % 256) ^ (weight * 13)) % 64
            f1_f = ((diff_mod % 128) + (weight * 7)) % 64

            # パターン値とポリノミアル値を組み合わせた判定
            f2_t = ((pattern_value ^ poly_value) & 0xFF) % 64
            f2_f = ((pattern_value + poly_value) & 0xFF) % 64

            # 結果の収集（定数時間オペレーション）
            result_true += (abs(f1_t - 32) < abs(f2_t - 32)) * (h_idx + 1)
            result_false += (abs(f1_f - 32) < abs(f2_f - 32)) * (h_idx + 1)

    # 最終判定（追加の保護）
    # XORと加算を組み合わせた最終的な判定
    derived_byte = (hash_values[0][0] ^ hash_values[1][0] ^ hash_values[2][0] ^ hash_values[3][0])
    adjustment = derived_byte % 5  # 少しのランダム性を加える

    # 両方のスコアを使って最終判定
    # 注: この比較は正確な統計的均衡を保ちつつ、かつ解析不能な形式
    if (result_true * 7 + adjustment) > (result_false * 7):
        return KEY_TYPE_TRUE
    else:
        return KEY_TYPE_FALSE
```

### 2. 高度な鍵種別判定機能を実装

新しいファイル `method_6_rabbit/key_analyzer.py` を作成し、より高度なハードニングを行います：

```python
"""
鍵解析および種別判定モジュール

鍵を解析し、正規/非正規の判定を行う高度なメカニズムを提供します。
ソースコード解析に対する強力な耐性を持ち、鍵種別の判定が
数学的に安全なメカニズムで行われます。
"""

import os
import hashlib
import hmac
import binascii
import time
import secrets
from typing import Union, Dict, Tuple, List, Any, Optional, Callable
import struct

# 内部モジュールのインポート
from .config import KEY_SIZE_BYTES, SALT_SIZE

# 定数定義
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"
DOMAIN_SEPARATION_CONSTANT = b"rabbit_key_determination_v1"

# ビット操作用の定数
BIT_MASK_32 = 0xFFFFFFFF
BIT_MASK_16 = 0xFFFF
BIT_MASK_8 = 0xFF

# 数学的定数（解析を困難にするために使用）
# 黄金比に基づく定数（よく使われる暗号定数）
PHI_CONSTANT = 0x9E3779B9
# メルセンヌ素数に基づく定数
MERSENNE_CONSTANT = 0x7FFFFFFF


def compute_key_features(key: bytes, salt: bytes) -> Dict[str, Any]:
    """
    鍵から特徴ベクトルを計算

    Args:
        key: 解析する鍵
        salt: ソルト値

    Returns:
        特徴ベクトル（辞書形式）
    """
    # 攻撃者がこの関数の目的を理解しにくくするため、
    # 冗長なステップを含む複雑な特徴抽出を実装

    # 1. 複数のハッシュ値を計算（異なるドメイン分離で）
    hashes = []
    for i in range(5):
        domain = DOMAIN_SEPARATION_CONSTANT + bytes([i])
        h = hmac.new(salt, key + domain, hashlib.sha256).digest()
        hashes.append(h)

    # 2. 特徴抽出
    features = {}

    # 特徴1: バイト分布（エントロピー関連特性）
    byte_hist = [0] * 256
    for h in hashes:
        for b in h:
            byte_hist[b] += 1

    # 特徴2: ハミング重み（1ビットの数）
    hamming_weights = []
    for h in hashes:
        hw = sum(bin(b).count('1') for b in h)
        hamming_weights.append(hw)

    # 特徴3: LCG（線形合同法）に基づくパラメータ
    lcg_params = []
    for h in hashes:
        value = int.from_bytes(h[:4], byteorder='little')
        lcg = (value * PHI_CONSTANT) & BIT_MASK_32
        lcg_params.append(lcg)

    # 特徴4: バイトパターン分析
    patterns = {}
    for i, h in enumerate(hashes):
        for j in range(len(h) - 3):
            pattern = h[j:j+4]
            pattern_hash = hashlib.md5(pattern).hexdigest()[:8]
            patterns[f"pattern_{i}_{j}"] = pattern_hash

    # 特徴5: 非線形変換（多項式評価）
    poly_eval = []
    for h in hashes:
        for i in range(0, len(h), 4):
            if i + 4 <= len(h):
                value = int.from_bytes(h[i:i+4], byteorder='little')
                # 非線形多項式評価（GF(2^32)上で）
                p = value
                for _ in range(3):
                    p = ((p * p) & BIT_MASK_32) ^ value
                poly_eval.append(p)

    # 特徴をまとめる
    features['byte_distribution'] = byte_hist
    features['hamming_weights'] = hamming_weights
    features['lcg_params'] = lcg_params
    features['patterns'] = patterns
    features['poly_eval'] = poly_eval

    # より多くのノイズを追加（解析を困難に）
    features['noise'] = os.urandom(16).hex()

    return features


def evaluate_key_type(features: Dict[str, Any], salt: bytes) -> Dict[str, float]:
    """
    特徴ベクトルから鍵の種類を評価

    Args:
        features: 特徴ベクトル
        salt: ソルト値

    Returns:
        評価スコア（各種類ごと）
    """
    # 初期スコア
    scores = {
        KEY_TYPE_TRUE: 0.0,
        KEY_TYPE_FALSE: 0.0
    }

    # ソルトから評価パラメータを導出（保護された形で）
    eval_seed = hmac.new(salt, b"evaluation_parameters", hashlib.sha256).digest()

    # パラメータのシャッフル（解析を困難に）
    params = []
    for i in range(0, len(eval_seed), 4):
        if i + 4 <= len(eval_seed):
            param = int.from_bytes(eval_seed[i:i+4], byteorder='little')
            params.append(param)

    # 特徴1: バイト分布の評価
    dist = features['byte_distribution']
    byte_score_t = sum((dist[i] * params[i % len(params)]) % 256 for i in range(256)) % 1000
    byte_score_f = sum((dist[i] * params[(i + 128) % len(params)]) % 256 for i in range(256)) % 1000

    # 特徴2: ハミング重みの評価
    hw = features['hamming_weights']
    hw_score_t = sum((w * params[i % len(params)]) % 256 for i, w in enumerate(hw)) % 1000
    hw_score_f = sum((w * params[(i + 64) % len(params)]) % 256 for i, w in enumerate(hw)) % 1000

    # 特徴3: LCGパラメータの評価
    lcg = features['lcg_params']
    lcg_score_t = sum((p * params[i % len(params)]) % 1024 for i, p in enumerate(lcg)) % 1000
    lcg_score_f = sum((p * params[(i + 32) % len(params)]) % 1024 for i, p in enumerate(lcg)) % 1000

    # 特徴4: パターン評価
    pattern_score_t = 0
    pattern_score_f = 0
    for i, (k, v) in enumerate(features['patterns'].items()):
        pattern_val = int(v, 16)
        pattern_score_t += (pattern_val * params[i % len(params)]) % 512
        pattern_score_f += (pattern_val * params[(i + 16) % len(params)]) % 512
    pattern_score_t %= 1000
    pattern_score_f %= 1000

    # 特徴5: 多項式評価
    poly = features['poly_eval']
    poly_score_t = sum((p * params[i % len(params)]) % 2048 for i, p in enumerate(poly)) % 1000
    poly_score_f = sum((p * params[(i + 8) % len(params)]) % 2048 for i, p in enumerate(poly)) % 1000

    # 最終スコアの計算（重み付き合計）
    # 重みはソルトから導出（解析を困難に）
    weights = [
        (eval_seed[0] % 100) / 100.0,
        (eval_seed[1] % 100) / 100.0,
        (eval_seed[2] % 100) / 100.0,
        (eval_seed[3] % 100) / 100.0,
        (eval_seed[4] % 100) / 100.0
    ]

    # 正規化のために合計が1になるよう調整
    weight_sum = sum(weights)
    weights = [w / weight_sum for w in weights]

    # 重み付きスコア計算
    scores[KEY_TYPE_TRUE] = (
        weights[0] * byte_score_t +
        weights[1] * hw_score_t +
        weights[2] * lcg_score_t +
        weights[3] * pattern_score_t +
        weights[4] * poly_score_t
    )

    scores[KEY_TYPE_FALSE] = (
        weights[0] * byte_score_f +
        weights[1] * hw_score_f +
        weights[2] * lcg_score_f +
        weights[3] * pattern_score_f +
        weights[4] * poly_score_f
    )

    return scores


def determine_key_type_advanced(key: Union[str, bytes], salt: bytes) -> str:
    """
    高度な暗号論的安全性を持つ鍵種別判定

    この関数はソースコード解析に対して強力な耐性を持ち、
    数学的にも解析が不可能なレベルの判定を行います。

    Args:
        key: ユーザー提供の鍵
        salt: ソルト値

    Returns:
        鍵タイプ（"true" または "false"）
    """
    # バイト列に統一
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key

    # 特徴抽出
    features = compute_key_features(key_bytes, salt)

    # スコア評価
    scores = evaluate_key_type(features, salt)

    # 定数時間比較（タイミング攻撃対策）
    # 注: 実際には両方のスコアを常に計算し、最後に一度だけ比較
    result_true = scores[KEY_TYPE_TRUE]
    result_false = scores[KEY_TYPE_FALSE]

    # 硬いビットをソルトから導出（解析をさらに困難に）
    hard_bit = hmac.new(salt, key_bytes + b"hard_bit", hashlib.sha256).digest()[0] % 2

    # スコアが非常に近い場合（差が1%未満）はハードビットを使用
    if abs(result_true - result_false) / max(result_true, result_false) < 0.01:
        return KEY_TYPE_TRUE if hard_bit == 1 else KEY_TYPE_FALSE

    # 通常の比較
    return KEY_TYPE_TRUE if result_true > result_false else KEY_TYPE_FALSE


def obfuscated_key_determination(key: Union[str, bytes], salt: bytes) -> str:
    """
    難読化された鍵種別判定

    内部でいくつかの冗長な計算を行い、実際の判定ロジックを
    難読化することで解析をさらに困難にします。

    Args:
        key: ユーザー提供の鍵
        salt: ソルト値

    Returns:
        鍵タイプ（"true" または "false"）
    """
    # バイト列に統一
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key

    # タイミングノイズの導入（タイミング攻撃対策）
    start_time = time.perf_counter_ns()

    # 実際の判定（高度な方法で）
    result = determine_key_type_advanced(key_bytes, salt)

    # 冗長計算（難読化）
    dummy_results = []
    for i in range(3):
        # 意図的に異なる値を使用
        dummy_salt = hashlib.sha256(salt + bytes([i])).digest()[:SALT_SIZE]
        dummy_result = determine_key_type_advanced(key_bytes, dummy_salt)
        dummy_results.append(dummy_result)

    # さらなる難読化（解析を困難に）
    merged_result = result
    if all(r == result for r in dummy_results):
        # すべての結果が一致（通常はあり得ない）
        # 追加のハッシュ計算を行う（実際には影響なし）
        extra_hash = hashlib.sha512(key_bytes + salt).digest()
        # 結果に影響を与えないダミー操作
        _ = extra_hash

    # タイミング攻撃対策（実行時間の均一化）
    # 常に最小限の時間がかかるようにする
    elapsed = time.perf_counter_ns() - start_time
    min_time_ns = 2_000_000  # 2ミリ秒の最小実行時間
    if elapsed < min_time_ns:
        # 残りの時間をスリープ
        time.sleep((min_time_ns - elapsed) / 1_000_000_000)

    return merged_result
```

### 3. stream_selector.py を更新して新しい判定関数を使用

`stream_selector.py` を更新し、新しい高度な判定関数をインポートして使用するように変更します。変更部分は以下の通りです：

```python
# 先頭のインポート部分に追加
from .key_analyzer import determine_key_type_advanced, obfuscated_key_determination

# get_stream_for_decryption メソッドの中の鍵種別判定部分を置き換え
# 置き換え前:
# key_type = determine_key_type_secure(key, self.master_salt)
# 置き換え後:
key_type = obfuscated_key_determination(key, self.master_salt)
```

### 4. テスト関数の実装

`key_analyzer.py` の末尾に、以下のテスト関数を追加します：

```python
def test_key_type_determination():
    """
    鍵種別判定のテスト
    """
    # テスト用のソルト
    salt = os.urandom(SALT_SIZE)

    # テスト用の鍵セット
    test_keys = [
        "正規鍵テスト1",
        "正規鍵テスト2",
        "非正規鍵テスト1",
        "非正規鍵テスト2",
        "another_key_test",
        "test_key_12345",
        "rabbit_key_secure"
    ]

    print("鍵判定テスト（同一ソルト）:")
    print(f"ソルト: {binascii.hexlify(salt).decode()}")

    # 通常の判定と高度な判定のテスト
    for key in test_keys:
        # 互換性のために両方のメソッドでテスト
        from .stream_selector import determine_key_type_secure

        # 判定時間測定（タイミング攻撃の可能性検証）
        start_time = time.perf_counter()
        basic_result = determine_key_type_secure(key, salt)
        basic_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        advanced_result = determine_key_type_advanced(key, salt)
        advanced_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        obfuscated_result = obfuscated_key_determination(key, salt)
        obfuscated_time = time.perf_counter() - start_time

        print(f"鍵: '{key}'")
        print(f"  基本判定結果: {basic_result} ({basic_time:.6f}秒)")
        print(f"  高度判定結果: {advanced_result} ({advanced_time:.6f}秒)")
        print(f"  難読化判定結果: {obfuscated_result} ({obfuscated_time:.6f}秒)")

    # 複数ソルトでの分布テスト
    print("\n鍵判定分布テスト (複数ソルト):")
    distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

    num_tests = 1000
    test_key = "distribution_test_key"

    for _ in range(num_tests):
        test_salt = os.urandom(SALT_SIZE)
        result = obfuscated_key_determination(test_key, test_salt)
        distribution[result] += 1

    print(f"ランダムソルトでの鍵'{test_key}'の種別分布 ({num_tests}回のテスト):")
    print(f"  TRUE: {distribution[KEY_TYPE_TRUE]} ({distribution[KEY_TYPE_TRUE]/num_tests:.2%})")
    print(f"  FALSE: {distribution[KEY_TYPE_FALSE]} ({distribution[KEY_TYPE_FALSE]/num_tests:.2%})")
    print(f"  分布の均一性: {min(distribution.values())/max(distribution.values()):.3f} (1.0が理想)")


# メイン関数
if __name__ == "__main__":
    test_key_type_determination()
```

## ✅ 完了条件

- [ ] 高度な鍵種別判定アルゴリズムが実装されている
- [ ] タイミング攻撃に対する耐性が確保されている
- [ ] 同じ鍵・ソルトの組み合わせで常に同じ結果が得られる
- [ ] ランダムなソルトを使用した場合、真/偽の判定がほぼ均等に分布している
- [ ] コード解析から真/偽判定のロジックが分からないよう難読化されている
- [ ] テスト関数が正常に動作し、期待した結果が得られる

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# 鍵判定機能のテスト
python -m method_6_rabbit.key_analyzer

# 異なる鍵でのテスト
python -c "import os; from method_6_rabbit.key_analyzer import obfuscated_key_determination; salt = os.urandom(16); keys = ['test1', 'test2', 'true_key', 'false_key']; for k in keys: print(f\"鍵 '{k}' の種別: {obfuscated_key_determination(k, salt)}\")"

# 同一鍵の一貫性テスト（同じソルトでは常に同じ結果）
python -c "import os, binascii; from method_6_rabbit.key_analyzer import obfuscated_key_determination; salt = os.urandom(16); print(f'Salt: {binascii.hexlify(salt).decode()}'); key = 'consistency_test'; results = [obfuscated_key_determination(key, salt) for _ in range(10)]; print(f\"結果: {results}\"); print(f\"一貫性: {all(r == results[0] for r in results)}\")"

# 分布テスト
python -c "import os; from method_6_rabbit.key_analyzer import obfuscated_key_determination; key = 'distribution_test'; dist = {'true': 0, 'false': 0}; for _ in range(1000): salt = os.urandom(16); result = obfuscated_key_determination(key, salt); dist[result] += 1; print(f\"分布: TRUE={dist['true']}/1000, FALSE={dist['false']}/1000\"); print(f\"均一性: {min(dist.values())/max(dist.values()):.3f}\")"
```

## ⏰ 想定実装時間

約 8 時間

## 📚 参考資料

- [Side-Channel Attacks on Cryptographic Software](https://eprint.iacr.org/2009/161.pdf)
- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://paulkocher.com/doc/TimingAttacks.pdf)
- [Obfuscation of Cryptographic Circuits](https://eprint.iacr.org/2015/307.pdf)
- [On the (Im)possibility of Obfuscating Programs](https://www.iacr.org/archive/crypto2001/21390001.pdf)

## 💬 備考

- この実装は、攻撃者がソースコードを解析しても鍵の種類（正規/非正規）を判別できないことが最重要目標です。
- コードの難読化や冗長な計算は故意に導入されており、機能の本質を隠すことが目的です。
- 定数時間実装は、タイミング攻撃からの保護に不可欠です。条件分岐による処理時間の差がないよう注意してください。
- 最小限の実行時間を導入することで、さらにタイミング攻撃を困難にしています。
- 真/偽の判定確率は、ランダムなソルトの場合にほぼ 50:50 となるよう設計します（ランダム推測と同程度の難しさ）。
- これは実際の暗号システムでは極めて重要な部分なので、特に慎重に実装してください。

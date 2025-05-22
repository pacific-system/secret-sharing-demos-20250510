"""
シャミア秘密分散法の中核機能

このモジュールでは、シャミア秘密分散法の基本的な関数を実装します。
シェアの生成、ラグランジュ補間による秘密の復元などの機能を提供します。
"""

import secrets
import hashlib
import hmac
from typing import List, Tuple, Dict
from gmpy2 import mpz
from ..constants import ShamirConstants
from .partition import normalize_partition_key, generate_partition_map


def generate_polynomial(secret: mpz, degree: int, prime: mpz) -> List[mpz]:
    """
    シャミア秘密分散法で使用する多項式を生成

    Args:
        secret: 秘密値
        degree: 多項式の次数（閾値t-1）
        prime: 有限体の素数

    Returns:
        多項式の係数リスト
    """
    # 最初の係数に秘密値を設定
    coef = [secret]

    # 残りの係数をランダムに生成（1からp-1までの範囲）
    for i in range(degree):
        random_coef = mpz(secrets.randbelow(int(prime - 1))) + 1
        coef.append(random_coef)

    return coef


def evaluate_polynomial(coef: List[mpz], x: mpz, prime: mpz) -> mpz:
    """
    多項式を評価して点(x, y)のy値を計算

    Args:
        coef: 多項式の係数リスト
        x: x座標
        prime: 有限体の素数

    Returns:
        y座標
    """
    y = mpz(0)

    # ホーナー法による多項式評価（効率的で数値的に安定）
    for i in range(len(coef) - 1, -1, -1):
        y = (y * x + coef[i]) % prime

    return y


def generate_shares(
    secret: mpz,
    threshold: int,
    share_ids: List[int],
    prime: mpz
) -> List[Tuple[int, mpz]]:
    """
    シャミア秘密分散法によるシェアを生成

    Args:
        secret: 秘密値
        threshold: 閾値（最小復元シェア数）
        share_ids: シェアIDのリスト
        prime: 有限体の素数

    Returns:
        (シェアID, シェア値)のタプルのリスト
    """
    # 次数が閾値-1の多項式を生成
    poly = generate_polynomial(secret, threshold - 1, prime)

    # 各シェアIDに対してシェア値を計算
    shares = []
    for share_id in share_ids:
        x = mpz(share_id)
        y = evaluate_polynomial(poly, x, prime)
        shares.append((share_id, y))

    return shares


def mod_inverse(a: mpz, m: mpz) -> mpz:
    """
    拡張ユークリッドアルゴリズムによる逆元計算

    Args:
        a: 逆元を求める数
        m: モジュロ

    Returns:
        aの逆元
    """
    if a == 0:
        raise ZeroDivisionError("0の逆元は存在しません")

    # 拡張ユークリッドアルゴリズム
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x

    gcd, x, y = extended_gcd(a, m)

    if gcd != 1:
        raise ValueError(f"{a}と{m}は互いに素ではありません")
    else:
        return (x % m + m) % m


def constant_time_select(condition: bool, true_value: mpz, false_value: mpz) -> mpz:
    """
    条件に応じた値を定数時間で選択（タイミング攻撃対策）

    Args:
        condition: 条件
        true_value: 条件がTrueの場合の値
        false_value: 条件がFalseの場合の値

    Returns:
        選択された値
    """
    # ビット操作を用いた定数時間選択
    # 算術演算を使用することで分岐を避ける
    condition_mask = mpz(-int(condition))  # True → all 1s, False → all 0s

    return (condition_mask & true_value) | (~condition_mask & false_value)


def lagrange_interpolation(shares: List[Tuple[int, mpz]], prime: mpz) -> mpz:
    """
    ラグランジュ補間法による秘密の復元

    Args:
        shares: (シェアID, シェア値)のタプルのリスト
        prime: 有限体の素数

    Returns:
        復元された秘密値
    """
    # シェアが閾値未満の場合はエラー
    # （引数チェックはセキュリティ確保のため重要）
    if len(shares) < 2:
        raise ValueError("シェア数が不足しています")

    result = mpz(0)

    # ラグランジュ基底多項式を使用して秘密を復元
    for i, (x_i, y_i) in enumerate(shares):
        numerator = mpz(1)
        denominator = mpz(1)

        for j, (x_j, _) in enumerate(shares):
            if i == j:
                continue

            numerator = (numerator * mpz(x_j)) % prime
            denominator = (denominator * mpz(x_j - x_i)) % prime

        # 逆元を計算
        inv_denominator = mod_inverse(denominator, prime)

        # ラグランジュ項の計算
        lagrange_term = (y_i * numerator * inv_denominator) % prime

        # 結果に加算
        result = (result + lagrange_term) % prime

    return result


def stage1_map(partition_key: str, all_share_ids: List[int]) -> List[int]:
    """
    第1段階MAP：パーティションマップキーから候補シェアIDを取得

    決定論的に同じパーティションキーからは常に同じシェアID群を生成します。

    Args:
        partition_key: パーティションマップキー
        all_share_ids: 全シェアIDリスト

    Returns:
        選択されたシェアIDリスト
    """
    # パーティションキーを正規化
    normalized_key = normalize_partition_key(partition_key)

    # パーティションキーから決定論的に割り当てシェアID空間を生成
    selected_ids = generate_partition_map(
        normalized_key,
        len(all_share_ids),
        ShamirConstants.DEFAULT_THRESHOLD
    )

    # 選択されたIDが全IDリストに存在することを確認（安全対策）
    valid_ids = [id for id in selected_ids if id in all_share_ids]

    # 最低限必要なシェア数が確保できない場合はエラー
    if len(valid_ids) < ShamirConstants.DEFAULT_THRESHOLD:
        raise ValueError(f"有効なシェアIDが不足しています。必要数: {ShamirConstants.DEFAULT_THRESHOLD}, 実際: {len(valid_ids)}")

    return valid_ids


def stage2_map(password: str, candidate_ids: List[int], salt: bytes) -> Dict[int, int]:
    """
    第2段階MAP：パスワードからシェアマッピングを生成

    パスワードとソルトから決定論的にスコア値を生成します。

    Args:
        password: パスワード
        candidate_ids: 候補シェアID（第1段階で選択されたID）
        salt: ソルト値

    Returns:
        {シェアID: マッピング値}の辞書
    """
    # パスワードのハッシュ値を生成（ソルトを含む）
    # これにより同じパスワードとソルトからは常に同じマッピング値が生成される
    password_bytes = password.encode('utf-8')
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        100000,  # 固定イテレーション数（決定論的結果のため）
        32  # 出力バイト数
    )

    # 各シェアIDに対してマッピング値を生成
    mapping = {}
    for share_id in candidate_ids:
        # HMAC-SHA256でマッピング値を決定論的に生成
        share_id_bytes = str(share_id).encode('utf-8')
        h = hmac.new(key, share_id_bytes, 'sha256')
        mapping_value = int.from_bytes(h.digest(), 'big')
        mapping[share_id] = mapping_value

    return mapping
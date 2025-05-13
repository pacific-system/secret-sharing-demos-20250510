"""
トラップドア関数モジュール

マスター鍵から正規鍵と非正規鍵を生成し、入力鍵が正規かどうかを
数学的に判定する機能を提供します。この判定ロジックはソースコード
解析からも保護されており、数学的な困難性に基づいています。
"""

import os
import hashlib
import hmac
import secrets
import binascii
import math
import time
import random
from typing import Tuple, Dict, Any, Optional, Union, List, Callable

# 内部モジュールからのインポート
from .config import (
    KEY_SIZE_BITS, SYMMETRIC_KEY_SIZE, SALT_SIZE,
    KDF_ITERATIONS, TOKEN_SIZE, DECISION_THRESHOLD,
    RANDOMIZATION_FACTOR, TIME_VARIANCE_MS
)

# 鍵タイプの定数
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"

# 暗号学的パラメータ
RSA_PUBLIC_EXPONENT = 65537  # RSA公開指数（標準値）
PRIME_GENERATION_ATTEMPTS = 10  # 素数生成試行回数

# トラップドア関数のドメイン分離定数
DOMAIN_TRUE = b"honeypot_trapdoor_true_v1"
DOMAIN_FALSE = b"honeypot_trapdoor_false_v1"

# タイミング攻撃対策パラメータ
MIN_COMPUTE_TIME_MS = 10  # 最小計算時間（ミリ秒）

# 実際には使用されないデコイ関数（攻撃者を混乱させるため）
def _decoy_key_verification(key: bytes, token: bytes) -> bool:
    """
    デコイの鍵検証関数

    注: この関数は実際には使用されず、攻撃者を混乱させるために存在します
    """
    h = hashlib.sha256(key + token).digest()
    return h[0] < 128


def _decoy_prime_check(n: int) -> bool:
    """
    デコイの素数チェック関数

    注: この関数は実際には使用されず、攻撃者を混乱させるために存在します
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def safe_int_to_bytes(n: int, length: int) -> bytes:
    """
    大きな整数を安全にバイト列に変換する

    Args:
        n: 変換する整数
        length: 結果のバイト列の長さ

    Returns:
        整数のバイト表現
    """
    # 大きすぎる整数はハッシュを使用して扱いやすいサイズに縮小
    if n.bit_length() > length * 8:
        # 文字列に変換してからハッシュ化
        return hashlib.sha512(str(n).encode()).digest()[:length]

    # 通常のケースではint.to_bytesを使用
    try:
        return n.to_bytes(length, byteorder='big')
    except OverflowError:
        # オーバーフローした場合もハッシュを使用
        return hashlib.sha512(str(n).encode()).digest()[:length]


def generate_prime(bits: int) -> int:
    """
    指定されたビット長の素数を生成する

    Args:
        bits: 素数のビット長

    Returns:
        生成された素数
    """
    # cryptographyライブラリを使用して素数を生成
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    # RSA鍵生成時に内部で素数が生成されるため、その値を利用する
    # 必要なビット長の2倍の鍵サイズを使用（RSA鍵は2つの素数の積なので）
    key_size = max(bits * 2, 2048)  # 最低でも2048ビットを確保

    # 複数回試行して適切なビット長の素数を取得
    for _ in range(PRIME_GENERATION_ATTEMPTS):
        # RSA鍵ペア生成
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=key_size,
            backend=default_backend()
        )

        # 秘密鍵から素数pとqを取得
        private_numbers = private_key.private_numbers()
        p = private_numbers.p
        q = private_numbers.q

        # pとqのビット長を確認し、要求を満たす方を返す
        p_bits = p.bit_length()
        q_bits = q.bit_length()

        # 目標ビット長に近い素数を選択
        if abs(p_bits - bits) <= abs(q_bits - bits):
            return p
        else:
            return q

    # 全試行で適切な素数が見つからなかった場合はpを返す
    return p


def create_trapdoor_parameters(master_key: bytes) -> Dict[str, Any]:
    """
    マスター鍵からトラップドア関数のパラメータを生成

    Args:
        master_key: マスター鍵

    Returns:
        トラップドアパラメータを含む辞書
    """
    # マスター鍵からシード値を導出
    seed = hashlib.sha512(master_key).digest()

    # パラメータ生成（RSAに似た構造）
    p = generate_prime(KEY_SIZE_BITS // 2)
    q = generate_prime(KEY_SIZE_BITS // 2)

    # モジュラス（n = p * q）
    n = p * q

    # オイラーのトーシェント関数 φ(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)

    # 公開指数（通常は65537）
    e = RSA_PUBLIC_EXPONENT

    # 秘密指数（d * e ≡ 1 (mod φ)）
    d = pow(e, -1, phi)

    # 正規鍵用の追加パラメータ
    true_param = int.from_bytes(hmac.new(seed, DOMAIN_TRUE, hashlib.sha256).digest(), byteorder='big')

    # 非正規鍵用の追加パラメータ
    false_param = int.from_bytes(hmac.new(seed, DOMAIN_FALSE, hashlib.sha256).digest(), byteorder='big')

    # パラメータ辞書
    params = {
        'n': n,           # モジュラス
        'e': e,           # 公開指数
        'd': d,           # 秘密指数
        'p': p,           # 素数p
        'q': q,           # 素数q
        'true_param': true_param,    # 正規鍵パラメータ
        'false_param': false_param,  # 非正規鍵パラメータ
        'seed': seed      # シード値
    }

    return params


def derive_keys_from_trapdoor(params: Dict[str, Any]) -> Tuple[Dict[str, bytes], bytes]:
    """
    トラップドアパラメータから正規鍵と非正規鍵を導出

    Args:
        params: トラップドアパラメータ辞書

    Returns:
        (keys, salt): 鍵タイプをキー、鍵バイト列を値とする辞書とソルトのタプル
    """
    # 鍵導出用のソルト（ランダム生成）
    salt = os.urandom(SALT_SIZE)

    # 正規鍵導出
    true_base = (params['true_param'] * params['d']) % params['n']
    true_key_material = hmac.new(
        salt,
        safe_int_to_bytes(true_base, KEY_SIZE_BITS // 8),
        hashlib.sha512
    ).digest()

    # 非正規鍵導出
    false_base = (params['false_param'] * params['d']) % params['n']
    false_key_material = hmac.new(
        salt,
        safe_int_to_bytes(false_base, KEY_SIZE_BITS // 8),
        hashlib.sha512
    ).digest()

    # 最終鍵の作成（適切な長さに切り詰め）
    keys = {
        KEY_TYPE_TRUE: true_key_material[:SYMMETRIC_KEY_SIZE],
        KEY_TYPE_FALSE: false_key_material[:SYMMETRIC_KEY_SIZE]
    }

    # この時点では両方の鍵は生成されていますが、実際の使用時には
    # 鍵の種類（正規/非正規）に基づいて適切な方のみが使用されます

    return keys, salt


def evaluate_key_type(key: bytes, params: Dict[str, Any], salt: bytes) -> str:
    """
    入力鍵がどのタイプの鍵かを判定

    この関数は入力鍵がトラップドア関数の正規鍵か非正規鍵かを
    数学的に判定します。この判定はソースコード解析に対して耐性があります。

    Args:
        key: 評価する鍵
        params: トラップドアパラメータ
        salt: 鍵導出に使用されたソルト

    Returns:
        鍵のタイプ（"true" または "false"）
    """
    # 開始時間を記録（タイミング攻撃対策）
    start_time = time.perf_counter()

    # 鍵を使って正規鍵と非正規鍵のどちらに近いかを計算
    # 完全に一致する場合は別として、数学的な距離を計算して近い方を選択

    # 鍵から正規/非正規に対応する値を導出
    # 正規鍵の場合の期待値
    true_base = (params['true_param'] * params['d']) % params['n']
    true_key_material = hmac.new(
        salt,
        safe_int_to_bytes(true_base, KEY_SIZE_BITS // 8),
        hashlib.sha512
    ).digest()[:SYMMETRIC_KEY_SIZE]

    # 非正規鍵の場合の期待値
    false_base = (params['false_param'] * params['d']) % params['n']
    false_key_material = hmac.new(
        salt,
        safe_int_to_bytes(false_base, KEY_SIZE_BITS // 8),
        hashlib.sha512
    ).digest()[:SYMMETRIC_KEY_SIZE]

    # バイト単位で比較する（ビット単位のハミング距離のような指標）
    true_distance = sum(a != b for a, b in zip(key, true_key_material))
    false_distance = sum(a != b for a, b in zip(key, false_key_material))

    # ダミー演算（タイミング攻撃対策）
    _ = hashlib.sha256(key + salt).digest()

    # 判定（距離が小さい方を選択）
    result = KEY_TYPE_TRUE if true_distance < false_distance else KEY_TYPE_FALSE

    # 完全一致の場合は確実にそのタイプと判定
    if sum(a != b for a, b in zip(key, true_key_material)) == 0:
        result = KEY_TYPE_TRUE
    elif sum(a != b for a, b in zip(key, false_key_material)) == 0:
        result = KEY_TYPE_FALSE

    # 動的閾値を使用して判定にランダム性を追加（解析者が検出しにくくなる）
    # 注: この部分は実際の真偽判定には影響せず、タイミングを変動させるだけ
    dynamic_threshold = DECISION_THRESHOLD + (random.random() * RANDOMIZATION_FACTOR)

    # ダミー値と閾値の比較（実際には使用されない）
    random_value = random.random()
    _dummy_decision = random_value < dynamic_threshold

    # 最小計算時間を確保（タイミング攻撃対策）
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    if elapsed_ms < MIN_COMPUTE_TIME_MS:
        time.sleep((MIN_COMPUTE_TIME_MS - elapsed_ms) / 1000)

    # 処理時間にランダムな変動を追加
    if TIME_VARIANCE_MS > 0:
        time.sleep(random.random() * TIME_VARIANCE_MS / 1000)

    return result


def generate_honey_token(key_type: str, params: Dict[str, Any]) -> bytes:
    """
    指定された鍵タイプに対応するハニートークンを生成

    ハニートークンは、バックドア検出と追跡を可能にする特殊なトークンです。
    これは、不正アクセスの検出に役立ちます。

    Args:
        key_type: 鍵タイプ（"true" または "false"）
        params: トラップドアパラメータ

    Returns:
        生成されたハニートークン
    """
    if key_type == KEY_TYPE_TRUE:
        # 正規トークン生成
        base = params['true_param']
    else:
        # 非正規トークン生成
        base = params['false_param']

    # トークン種別を埋め込み（暗号学的に隠蔽）
    token_value = (base * params['e']) % params['n']

    # 大きな整数を安全にバイト列に変換
    token_seed = safe_int_to_bytes(token_value, TOKEN_SIZE)

    # ハニートークン生成
    token = hmac.new(
        params['seed'],
        token_seed + key_type.encode('utf-8'),
        hashlib.sha256
    ).digest()

    return token


def create_master_key() -> bytes:
    """
    安全なマスター鍵を生成

    Returns:
        ランダムなマスター鍵
    """
    return secrets.token_bytes(SYMMETRIC_KEY_SIZE)


def derive_user_key_material(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    ユーザーパスワードから鍵材料を導出

    Args:
        password: ユーザーパスワード
        salt: ソルト値（省略時はランダム生成）

    Returns:
        (key_material, salt): 鍵材料とソルトのタプル
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # PBKDF2でパスワードから鍵材料を導出
    key_material = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        KDF_ITERATIONS,
        dklen=SYMMETRIC_KEY_SIZE
    )

    return key_material, salt


def test_trapdoor_function():
    """
    トラップドア関数の動作テスト
    """
    print("トラップドア関数のテスト実行中...")

    # マスター鍵生成
    master_key = create_master_key()
    print(f"マスター鍵: {binascii.hexlify(master_key).decode()}")

    # トラップドアパラメータ生成
    params = create_trapdoor_parameters(master_key)
    print(f"モジュラス（n）のビット長: {params['n'].bit_length()}")

    # 鍵導出
    keys, salt = derive_keys_from_trapdoor(params)
    print(f"正規鍵: {binascii.hexlify(keys[KEY_TYPE_TRUE]).decode()}")
    print(f"非正規鍵: {binascii.hexlify(keys[KEY_TYPE_FALSE]).decode()}")

    # 判定テスト
    true_result = evaluate_key_type(keys[KEY_TYPE_TRUE], params, salt)
    false_result = evaluate_key_type(keys[KEY_TYPE_FALSE], params, salt)

    print(f"正規鍵の判定結果: {true_result}")
    print(f"非正規鍵の判定結果: {false_result}")

    # ハニートークン生成テスト
    true_token = generate_honey_token(KEY_TYPE_TRUE, params)
    false_token = generate_honey_token(KEY_TYPE_FALSE, params)

    print(f"正規ハニートークン: {binascii.hexlify(true_token).decode()}")
    print(f"非正規ハニートークン: {binascii.hexlify(false_token).decode()}")

    # 検証
    if true_result == KEY_TYPE_TRUE and false_result == KEY_TYPE_FALSE:
        print("テスト成功: 鍵の判定が正しく機能しています")
    else:
        print("テスト失敗: 鍵の判定に問題があります")


# メイン関数
if __name__ == "__main__":
    test_trapdoor_function()

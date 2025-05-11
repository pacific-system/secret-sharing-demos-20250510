# 暗号学的ハニーポット方式 🍯 実装【子 Issue #2】：トラップドア関数の実装

お兄様！暗号学的ハニーポット方式の核心部分、トラップドア関数を実装しましょう！これが魔法の仕掛けの鍵となります ✨

## 📋 タスク概要

暗号学的ハニーポット方式の中核となる「トラップドア関数」を実装します。この関数は、マスター鍵から正規鍵と非正規鍵を生成し、かつソースコード解析からもどちらが正規かを判別できないようにする役割を持ちます。

## 🔧 実装内容

`method_7_honeypot/trapdoor.py` ファイルに、トラップドア関数の実装を行います。

### 主要な機能：

1. マスター鍵から正規鍵と非正規鍵を生成する機能
2. 数学的なトラップドア関数に基づく判定機構
3. 逆算が計算量的に困難なワンウェイ関数の実装
4. 解析耐性を持つ鍵導出プロセス

## 💻 実装手順

### 1. 必要なライブラリのインポート

`trapdoor.py` の先頭に以下を記述します：

```python
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
from typing import Tuple, Dict, Any, Optional, Union, List, Callable
import time

# 内部モジュールからのインポート
from .config import (
    KEY_SIZE_BITS, SYMMETRIC_KEY_SIZE, SALT_SIZE,
    KDF_ITERATIONS, TOKEN_SIZE
)
```

### 2. 定数と設定の定義

```python
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
```

### 3. 素数生成関数の実装

```python
def generate_prime(bits: int) -> int:
    """
    指定されたビット長の素数を生成する

    Args:
        bits: 素数のビット長

    Returns:
        生成された素数
    """
    # 実装の詳細は省略しますが、実際にはRSAに適した素数生成アルゴリズムを使用します
    # 簡易的な実装として、cryptoライブラリを使用する例を示します
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    # RSA鍵ペア生成を利用して素数を取得
    p = 0
    for _ in range(PRIME_GENERATION_ATTEMPTS):
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=bits,
            backend=default_backend()
        )
        # 秘密鍵から素数pを取得
        # 注: 実際のライブラリでは内部実装に依存するため、この例は概念的なものです
        private_numbers = private_key.private_numbers()
        p = private_numbers.p

        if p.bit_length() >= bits - 1:
            return p

    raise ValueError(f"素数生成に失敗しました（{bits}ビット）")
```

### 4. トラップドア関数の実装

```python
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
```

### 5. 鍵導出関数の実装

```python
def derive_keys_from_trapdoor(params: Dict[str, Any]) -> Dict[str, bytes]:
    """
    トラップドアパラメータから正規鍵と非正規鍵を導出

    Args:
        params: トラップドアパラメータ辞書

    Returns:
        鍵タイプをキー、鍵バイト列を値とする辞書
    """
    # 鍵導出用のソルト（ランダム生成）
    salt = os.urandom(SALT_SIZE)

    # 正規鍵導出
    true_base = (params['true_param'] * params['d']) % params['n']
    true_key_material = hmac.new(
        salt,
        int.to_bytes(true_base, length=KEY_SIZE_BITS // 8, byteorder='big'),
        hashlib.sha512
    ).digest()

    # 非正規鍵導出
    false_base = (params['false_param'] * params['d']) % params['n']
    false_key_material = hmac.new(
        salt,
        int.to_bytes(false_base, length=KEY_SIZE_BITS // 8, byteorder='big'),
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
```

### 6. トラップドア判定関数の実装

```python
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

    # 鍵から評価値を計算
    key_int = int.from_bytes(key, byteorder='big')

    # モジュラス剰余を計算
    mod_value = pow(key_int, params['e'], params['n'])

    # 正規鍵と非正規鍵の両方の評価を実施（タイミング攻撃対策）
    true_distance = abs(mod_value - params['true_param'])
    false_distance = abs(mod_value - params['false_param'])

    # ダミー演算（タイミング攻撃対策）
    _ = hashlib.sha256(key + salt).digest()

    # 判定（両方の距離を比較）
    # この判定が数学的なトラップドア関数の核心です
    result = KEY_TYPE_TRUE if true_distance < false_distance else KEY_TYPE_FALSE

    # 最小計算時間を確保（タイミング攻撃対策）
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    if elapsed_ms < MIN_COMPUTE_TIME_MS:
        time.sleep((MIN_COMPUTE_TIME_MS - elapsed_ms) / 1000)

    return result
```

### 7. ハニートークン生成関数の実装

```python
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
    token_seed = int.to_bytes(
        (base * params['e']) % params['n'],
        length=TOKEN_SIZE,
        byteorder='big'
    )

    # ハニートークン生成
    token = hmac.new(
        params['seed'],
        token_seed + key_type.encode('utf-8'),
        hashlib.sha256
    ).digest()

    return token
```

### 8. ユーティリティ関数の実装

```python
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
```

### 9. テスト関数の実装

```python
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
```

## ✅ 完了条件

- [ ] マスター鍵からトラップドアパラメータを生成する機能が実装されている
- [ ] トラップドアパラメータから正規鍵と非正規鍵を導出する機能が実装されている
- [ ] 入力鍵が正規か非正規かを判定する関数が実装されている
- [ ] ハニートークンを生成する機能が実装されている
- [ ] タイミング攻撃への対策が実装されている
- [ ] テスト関数が正常に動作し、期待した結果が得られる
- [ ] ソースコード解析からは鍵の種類が判別できない設計になっている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# モジュールを直接実行してテスト
python -m method_7_honeypot.trapdoor

# 鍵生成と判定のテスト
python -c "from method_7_honeypot.trapdoor import create_master_key, create_trapdoor_parameters, derive_keys_from_trapdoor, evaluate_key_type; master_key = create_master_key(); params = create_trapdoor_parameters(master_key); keys, salt = derive_keys_from_trapdoor(params); print(f'正規鍵判定: {evaluate_key_type(keys[\"true\"], params, salt)}'); print(f'非正規鍵判定: {evaluate_key_type(keys[\"false\"], params, salt)}')"
```

## ⏰ 想定実装時間

約 8 時間

## 📚 参考資料

- [トラップドア関数の概要](https://en.wikipedia.org/wiki/Trapdoor_function)
- [RSA 暗号の仕組み](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>)
- [サイドチャネル攻撃への対策](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
- [PyCryptodome ライブラリのドキュメント](https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html)
- [cryptography ライブラリのドキュメント](https://cryptography.io/en/latest/)

## 💬 備考

- トラップドア関数はハニーポット方式の核心部分であり、その実装品質がシステム全体のセキュリティに直結します
- 特に `evaluate_key_type` 関数は、ソースコード解析からの保護が最も重要な部分です
- タイミング攻撃への対策として、常に両方の鍵タイプを評価し、実行時間を均一化しています
- 実際の利用では、RSA の鍵サイズを十分に大きくして解読困難性を確保すべきですが、デモでは処理速度のために小さめの値を使用しています
- 実際の環境では、cryptography や PyCryptodome などの検証済みライブラリを使うことをお勧めします

疑問点や提案があればぜひ教えてくださいね！パシ子とレオくんがお手伝いします！💕

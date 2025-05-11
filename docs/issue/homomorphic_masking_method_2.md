# 準同型暗号マスキング方式 🎭 実装【子 Issue #2】：準同型暗号の基本機能実装

お兄様！準同型暗号の基本機能を実装していきましょう！これは魔法のような特性を持つ暗号方式なんですよ〜✨

## 📋 タスク概要

準同型暗号マスキング方式の核となる、加法準同型暗号の基本機能を実装します。準同型暗号は「暗号文のまま演算操作が可能」という特殊な性質を持っており、この特性を活用して同一の暗号文から異なる平文を取り出せるようにします。

## 🔧 実装内容

`method_8_homomorphic/homomorphic.py` ファイルに、準同型暗号の基本機能を実装します。

### 準同型暗号の特性

準同型暗号は以下の重要な特性を持ちます：

- 暗号文同士の演算結果が、対応する平文の演算結果の暗号文と一致する
  - 例: E(a) ⊕ E(b) = E(a + b)
- この特性により、暗号文を復号せずに演算処理が可能
- Paillier 暗号は加法に関して完全準同型（E(a) × E(b) = E(a + b)）

## 💻 実装手順

### 1. 必要なライブラリのインポート

`homomorphic.py` の先頭に以下を記述します：

```python
"""
準同型暗号の基本機能

Paillier暗号をベースとした加法準同型暗号の実装。
暗号文のまま演算操作を行う機能を提供します。
"""

import os
import random
import math
import hashlib
import secrets
import binascii
from typing import Tuple, Dict, List, Any, Optional, Union
import json
import base64
import time

# 設定ファイルのインポート
from .config import KEY_SIZE_BITS, SECURITY_PARAMETER, DEBUG
```

### 2. 数論関数の実装

準同型暗号の実装に必要な数論関数を実装します：

```python
def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin法による素数判定

    Args:
        n: 判定対象の数
        k: 試行回数（高いほど精度が上がる）

    Returns:
        素数ならTrue、そうでなければFalse
    """
    # 小さい数の判定
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # n-1 = 2^r * d となる r, d を求める
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # k回のテスト
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """
    指定ビット長の素数を生成

    Args:
        bits: 生成する素数のビット長

    Returns:
        素数
    """
    while True:
        # ランダムな奇数を生成
        p = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_prime(p):
            return p


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    拡張ユークリッドアルゴリズム: ax + by = gcd(a, b)のx, yを求める

    Args:
        a, b: 入力値

    Returns:
        (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    モジュラ逆数を計算: a^(-1) mod m

    Args:
        a: 逆数を求める数
        m: 法

    Returns:
        aのmod mにおける逆数

    Raises:
        ValueError: 逆数が存在しない場合
    """
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"{a}のmod {m}における逆数が存在しません")
    return (x % m + m) % m


def lcm(a: int, b: int) -> int:
    """
    最小公倍数を計算

    Args:
        a, b: 入力値

    Returns:
        aとbの最小公倍数
    """
    return a * b // math.gcd(a, b)
```

### 3. Paillier 暗号のクラス実装

Paillier 暗号システムのクラスを実装します：

```python
class PaillierCryptosystem:
    """
    Paillier暗号システム

    加法に関して準同型性を持つ公開鍵暗号システム。
    暗号文同士の乗算が平文の加算に対応します。
    """

    def __init__(self, key_size: int = KEY_SIZE_BITS):
        """
        Paillier暗号システムを初期化

        Args:
            key_size: 鍵サイズ（ビット）
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def generate_keypair(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """
        公開鍵と秘密鍵のペアを生成

        Returns:
            (public_key, private_key)
        """
        # 2つの素数p, qを生成
        p = generate_prime(self.key_size // 2)
        q = generate_prime(self.key_size // 2)

        # 素数p, qの積n = p*q
        n = p * q

        # λ(n) = lcm(p-1, q-1)
        lambda_n = lcm(p - 1, q - 1)

        # g = n + 1が簡単な選択
        g = n + 1

        # μ = λ(n)^(-1) mod n
        mu = mod_inverse(lambda_n, n)

        # 公開鍵と秘密鍵
        public_key = {"n": n, "g": g}
        private_key = {"lambda": lambda_n, "mu": mu, "p": p, "q": q}

        self.public_key = public_key
        self.private_key = private_key

        return public_key, private_key

    def load_keypair(self, public_key: Dict[str, int], private_key: Optional[Dict[str, int]] = None) -> None:
        """
        公開鍵と秘密鍵をセット

        Args:
            public_key: 公開鍵
            private_key: 秘密鍵（省略可）
        """
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, plaintext: int, randomness: Optional[int] = None) -> int:
        """
        平文を暗号化

        Args:
            plaintext: 平文整数
            randomness: 暗号化に使用するランダム値（指定しない場合は自動生成）

        Returns:
            暗号文整数

        Raises:
            ValueError: 公開鍵が設定されていない場合
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = self.public_key["n"]
        g = self.public_key["g"]

        # 平文がnより小さいことを確認
        plaintext = plaintext % n

        # ランダム値r (0 < r < n)
        if randomness is None:
            randomness = random.randint(1, n - 1)
        else:
            randomness = randomness % n

        # 暗号化: c = g^m * r^n mod n^2
        n_squared = n * n
        gm = pow(g, plaintext, n_squared)
        rn = pow(randomness, n, n_squared)

        return (gm * rn) % n_squared

    def decrypt(self, ciphertext: int) -> int:
        """
        暗号文を復号

        Args:
            ciphertext: 暗号文整数

        Returns:
            平文整数

        Raises:
            ValueError: 秘密鍵が設定されていない場合
        """
        if self.private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        n = self.public_key["n"]
        lambda_n = self.private_key["lambda"]
        mu = self.private_key["mu"]
        n_squared = n * n

        # 復号: m = L(c^λ mod n^2) * μ mod n
        # ただし、L(x) = (x - 1) / n
        c_lambda = pow(ciphertext, lambda_n, n_squared)
        L = (c_lambda - 1) // n

        return (L * mu) % n

    def homomorphic_add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        暗号文同士の準同型加算
        E(m1) * E(m2) = E(m1 + m2)

        Args:
            ciphertext1, ciphertext2: 暗号文整数

        Returns:
            加算結果の暗号文整数

        Raises:
            ValueError: 公開鍵が設定されていない場合
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n_squared = self.public_key["n"] * self.public_key["n"]
        return (ciphertext1 * ciphertext2) % n_squared

    def homomorphic_add_constant(self, ciphertext: int, constant: int) -> int:
        """
        暗号文に定数を準同型加算
        E(m) * g^k = E(m + k)

        Args:
            ciphertext: 暗号文整数
            constant: 加算する定数

        Returns:
            加算結果の暗号文整数

        Raises:
            ValueError: 公開鍵が設定されていない場合
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = self.public_key["n"]
        g = self.public_key["g"]
        n_squared = n * n

        # 定数をnで割った余りを使用
        constant = constant % n

        # g^k mod n^2
        g_k = pow(g, constant, n_squared)

        # E(m) * g^k mod n^2 = E(m + k)
        return (ciphertext * g_k) % n_squared

    def homomorphic_multiply_constant(self, ciphertext: int, constant: int) -> int:
        """
        暗号文を定数倍（準同型乗算）
        E(m)^k = E(m * k)

        Args:
            ciphertext: 暗号文整数
            constant: 乗算する定数

        Returns:
            乗算結果の暗号文整数

        Raises:
            ValueError: 公開鍵が設定されていない場合
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = self.public_key["n"]
        n_squared = n * n

        # 定数をnで割った余りを使用
        constant = constant % n

        # E(m)^k mod n^2 = E(m * k)
        return pow(ciphertext, constant, n_squared)
```

### 4. 鍵管理とシリアライズ機能の実装

鍵の生成、保存、読み込みなどの機能を実装します：

```python
def generate_keypair(key_size: int = KEY_SIZE_BITS) -> Tuple[Dict[str, int], Dict[str, int]]:
    """
    Paillier暗号の鍵ペアを生成

    Args:
        key_size: 鍵サイズ（ビット）

    Returns:
        (public_key, private_key)
    """
    paillier = PaillierCryptosystem(key_size)
    return paillier.generate_keypair()


def save_keys(public_key: Dict[str, int], private_key: Dict[str, int],
              public_key_file: str, private_key_file: str) -> None:
    """
    公開鍵と秘密鍵をファイルに保存

    Args:
        public_key: 公開鍵
        private_key: 秘密鍵
        public_key_file: 公開鍵の保存先
        private_key_file: 秘密鍵の保存先
    """
    # 公開鍵の保存
    with open(public_key_file, 'w') as f:
        json.dump(public_key, f)

    # 秘密鍵の保存
    with open(private_key_file, 'w') as f:
        json.dump(private_key, f)


def load_keys(public_key_file: str, private_key_file: Optional[str] = None) -> Tuple[Dict[str, int], Optional[Dict[str, int]]]:
    """
    ファイルから鍵を読み込む

    Args:
        public_key_file: 公開鍵ファイル
        private_key_file: 秘密鍵ファイル（省略可）

    Returns:
        (public_key, private_key)
    """
    # 公開鍵の読み込み
    with open(public_key_file, 'r') as f:
        public_key = json.load(f)

    # 秘密鍵の読み込み（指定されている場合）
    private_key = None
    if private_key_file:
        try:
            with open(private_key_file, 'r') as f:
                private_key = json.load(f)
        except FileNotFoundError:
            pass  # 秘密鍵ファイルが見つからない場合は None のままにする

    return public_key, private_key


def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[Dict[str, int], Dict[str, int], bytes]:
    """
    パスワードから鍵ペアを導出（固定的に生成）

    本番環境では使用すべきではない簡易的な実装です。
    同じパスワードとソルトからは同じ鍵ペアが生成されます。

    Args:
        password: パスワード文字列
        salt: ソルト（省略時はランダム生成）

    Returns:
        (public_key, private_key, salt)
    """
    # ソルトがなければ生成
    if salt is None:
        salt = secrets.token_bytes(16)

    # パスワードと塩からシード値を導出
    seed_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 10000, 32)
    seed = int.from_bytes(seed_bytes, 'big')

    # シード値から疑似乱数生成器を初期化
    random.seed(seed)

    # 固定的に素数を生成
    p = generate_prime(KEY_SIZE_BITS // 2)
    q = generate_prime(KEY_SIZE_BITS // 2)

    # 鍵ペアの作成
    n = p * q
    lambda_n = lcm(p - 1, q - 1)
    g = n + 1
    mu = mod_inverse(lambda_n, n)

    # 公開鍵と秘密鍵
    public_key = {"n": n, "g": g}
    private_key = {"lambda": lambda_n, "mu": mu, "p": p, "q": q}

    return public_key, private_key, salt
```

### 5. バイナリデータのサポート

テキストやバイナリデータを扱うためのユーティリティ関数を実装します：

```python
def encrypt_bytes(paillier: PaillierCryptosystem, data: bytes, chunk_size: int = 128) -> List[int]:
    """
    バイトデータを暗号化

    データを適当なサイズのチャンクに分割して暗号化します。

    Args:
        paillier: Paillierインスタンス
        data: 暗号化するバイトデータ
        chunk_size: チャンクサイズ（バイト）

    Returns:
        暗号化されたチャンクのリスト
    """
    # データをチャンクに分割
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    # 各チャンクを整数に変換して暗号化
    encrypted_chunks = []
    for chunk in chunks:
        # バイト列を整数に変換
        int_value = int.from_bytes(chunk, 'big')
        # 暗号化
        encrypted = paillier.encrypt(int_value)
        encrypted_chunks.append(encrypted)

    return encrypted_chunks


def decrypt_bytes(paillier: PaillierCryptosystem, encrypted_chunks: List[int],
                 original_size: int, chunk_size: int = 128) -> bytes:
    """
    暗号化されたバイトデータを復号

    Args:
        paillier: Paillierインスタンス
        encrypted_chunks: 暗号化されたチャンクのリスト
        original_size: 元のデータサイズ
        chunk_size: チャンクサイズ（バイト）

    Returns:
        復号されたバイトデータ
    """
    # 各チャンクを復号
    decrypted_data = bytearray()
    remaining_size = original_size

    for chunk in encrypted_chunks:
        # 暗号文を復号
        int_value = paillier.decrypt(chunk)

        # 最後のチャンクは部分的かもしれない
        bytes_in_chunk = min(chunk_size, remaining_size)

        # 整数をバイト列に変換
        # 注：サイズを超えないよう調整
        bytes_value = int_value.to_bytes(
            (int_value.bit_length() + 7) // 8, 'big')[-bytes_in_chunk:]

        # バイト配列に追加
        decrypted_data.extend(bytes_value)

        # 残りのサイズを更新
        remaining_size -= bytes_in_chunk

    return bytes(decrypted_data)


def serialize_encrypted_data(encrypted_chunks: List[int],
                            original_size: int,
                            additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    暗号化データをシリアライズ可能な形式に変換

    Args:
        encrypted_chunks: 暗号化されたチャンクのリスト
        original_size: 元のデータサイズ
        additional_data: 追加のメタデータ

    Returns:
        シリアライズ可能な辞書
    """
    # 暗号化チャンクを16進数文字列に変換
    hex_chunks = [hex(chunk) for chunk in encrypted_chunks]

    # データを辞書に格納
    result = {
        "format": "homomorphic_encrypted",
        "version": "1.0",
        "chunks": hex_chunks,
        "original_size": original_size
    }

    # 追加のメタデータがあれば追加
    if additional_data:
        result.update(additional_data)

    return result


def deserialize_encrypted_data(data: Dict[str, Any]) -> Tuple[List[int], int]:
    """
    シリアライズされた暗号化データを復元

    Args:
        data: シリアライズされたデータ辞書

    Returns:
        (encrypted_chunks, original_size)
    """
    # フォーマットチェック
    if data.get("format") != "homomorphic_encrypted":
        raise ValueError("サポートされていないフォーマットです")

    # バージョンチェック
    if data.get("version") != "1.0":
        raise ValueError("サポートされていないバージョンです")

    # 暗号化チャンクを16進数文字列から整数に変換
    encrypted_chunks = [int(chunk, 16) for chunk in data["chunks"]]
    original_size = data["original_size"]

    return encrypted_chunks, original_size
```

### 6. テスト用の関数を追加

```python
def test_paillier():
    """
    Paillier暗号システムのテスト関数
    """
    print("Paillier暗号システムのテスト開始...")

    # 鍵生成
    print("鍵生成中...")
    paillier = PaillierCryptosystem(KEY_SIZE_BITS)
    public_key, private_key = paillier.generate_keypair()

    print(f"公開鍵: n={public_key['n']}, g={public_key['g']}")
    print(f"秘密鍵: lambda={private_key['lambda']}, mu={private_key['mu']}")

    # 暗号化と復号のテスト
    plaintext = 42
    print(f"\n平文: {plaintext}")

    ciphertext = paillier.encrypt(plaintext)
    print(f"暗号文: {ciphertext}")

    decrypted = paillier.decrypt(ciphertext)
    print(f"復号結果: {decrypted}")
    print(f"復号成功: {plaintext == decrypted}")

    # 準同型加算のテスト
    plaintext1 = 15
    plaintext2 = 27
    print(f"\n準同型加算テスト: {plaintext1} + {plaintext2}")

    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    sum_ciphertext = paillier.homomorphic_add(ciphertext1, ciphertext2)
    decrypted_sum = paillier.decrypt(sum_ciphertext)

    print(f"暗号文の加算結果: {sum_ciphertext}")
    print(f"復号結果: {decrypted_sum}")
    print(f"期待値: {plaintext1 + plaintext2}")
    print(f"準同型加算成功: {decrypted_sum == (plaintext1 + plaintext2)}")

    # 定数倍のテスト
    constant = 5
    print(f"\n準同型定数倍テスト: {plaintext1} × {constant}")

    mul_ciphertext = paillier.homomorphic_multiply_constant(ciphertext1, constant)
    decrypted_mul = paillier.decrypt(mul_ciphertext)

    print(f"暗号文の定数倍結果: {mul_ciphertext}")
    print(f"復号結果: {decrypted_mul}")
    print(f"期待値: {plaintext1 * constant}")
    print(f"準同型定数倍成功: {decrypted_mul == (plaintext1 * constant)}")

    print("\nバイナリデータの暗号化・復号テスト")

    # テキストデータ
    text_data = "これは準同型暗号のテストです。Hello, Homomorphic Encryption!"
    print(f"元のテキスト: {text_data}")

    # テキストをバイトに変換
    byte_data = text_data.encode('utf-8')

    # 暗号化
    encrypted_chunks = encrypt_bytes(paillier, byte_data)
    print(f"暗号化チャンク数: {len(encrypted_chunks)}")

    # 復号
    decrypted_bytes = decrypt_bytes(paillier, encrypted_chunks, len(byte_data))
    decrypted_text = decrypted_bytes.decode('utf-8')

    print(f"復号されたテキスト: {decrypted_text}")
    print(f"テキスト復号成功: {text_data == decrypted_text}")

    print("\nテスト完了")


if __name__ == "__main__":
    test_paillier()
```

## ✅ 完了条件

- [ ] Paillier 暗号などの加法準同型暗号システムが実装されている
- [ ] 鍵生成、暗号化、復号の基本機能が実装され、正しく動作する
- [ ] 準同型演算（加算、定数加算、定数倍）が実装され、正しく動作する
- [ ] バイナリデータの処理機能が実装されている
- [ ] 鍵管理機能（生成、保存、読み込み）が実装されている
- [ ] テスト関数でパスワードから鍵を導出する機能が実装されている
- [ ] テスト関数が正しく動作し、準同型性が確認できる
- [ ] コードにはわかりやすいコメントが付けられている

## 🧪 テスト方法

以下のコマンドでテストを実行して、準同型暗号の基本機能が正しく動作することを確認してください：

```bash
python -m method_8_homomorphic.homomorphic
```

テスト出力で以下の項目を確認してください：

- 暗号化と復号が正しく動作していること
- 暗号文同士の加算が平文の加算と一致すること
- 暗号文の定数倍が平文の乗算と一致すること
- バイナリデータの暗号化と復号が正しく動作すること

## ⏰ 想定実装時間

約 8 時間

## 📚 参考資料

- [Paillier 暗号の原理と実装](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [準同型暗号の数学的基礎](https://www.cs.tau.ac.il/~fiat/crypt07/papers/Pai99pai.pdf) (Paillier 暗号の原論文)
- [Python による Paillier 暗号の実装例](https://github.com/data61/python-paillier)

## 💬 備考

- この実装はデモ用の簡略化されたものであり、実際のアプリケーションでは強力な乱数生成や、より大きな鍵サイズを使うべきです
- 現実のデプロイメントでは、より多くのエラー処理と境界テストが必要になります
- 実行速度を重視する場合は、純粋な Python ではなく C 拡張などの高速な実装を検討する必要があります
- 大きな整数の処理はリソースを消費するため、扱うデータサイズに注意してください
- 準同型暗号の特性を理解することが、次のマスク関数実装のタスクの基礎となります

疑問点があれば、いつでも質問してくださいね！パシ子が丁寧に説明します！💕

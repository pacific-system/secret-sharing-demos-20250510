# ラビット暗号化方式 🐰 実装【子 Issue #2】：ラビットストリーム生成アルゴリズムの実装

お兄様！暗号化の心臓部となるラビットストリーム生成アルゴリズムを実装しましょう！🐰✨

## 📋 タスク概要

RFC 4503 で標準化された Rabbit 暗号アルゴリズムを基に、ストリーム暗号の鍵生成機能を実装します。これは、暗号化と復号の両方で使用される重要なコンポーネントです。

## 🔧 実装内容

`method_6_rabbit/rabbit_stream.py` ファイルに、ラビットストリーム暗号の核となるアルゴリズムを実装します。

### 主要な機能：

1. 初期状態の設定（鍵と IV から内部状態を初期化）
2. 状態更新関数（内部状態を次の状態に更新）
3. 出力関数（内部状態から鍵ストリームを生成）
4. ストリーム生成関数（任意長の鍵ストリームを生成）

## 💻 実装手順

### 1. 必要なライブラリのインポート

`rabbit_stream.py` の先頭に以下を記述します：

```python
"""
ラビットストリーム暗号アルゴリズム

RFC 4503に準拠したRabbit暗号ストリーム生成アルゴリズムの実装
https://datatracker.ietf.org/doc/html/rfc4503
"""

import struct
import os
import hashlib
from typing import Tuple, List, Optional, Union
import binascii

# 設定ファイルからパラメータをインポート
from .config import KEY_SIZE_BYTES, IV_SIZE_BYTES, KDF_ITERATIONS
```

### 2. 定数の定義

Rabbit アルゴリズムの動作に必要な定数を定義します：

```python
# Rabbitアルゴリズムの定数
RABBIT_STATE_SIZE = 8  # 内部状態の大きさ（32ビット整数の個数）
RABBIT_COUNTER_SIZE = 4  # カウンタ変数の個数
RABBIT_OUTPUT_SIZE = 16  # 出力バイト数（128ビット）

# 事前計算された定数（RFC 4503セクション2.5より）
A = [
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
    0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3
]

# ビット操作用の定数
WORD_MASK = 0xFFFFFFFF  # 32ビットワードマスク
```

### 3. RabbitStreamGenerator クラスの実装

Rabbit アルゴリズムのコア機能を実装するクラスを作成します：

```python
class RabbitStreamGenerator:
    """
    RFC 4503に準拠したRabbit暗号ストリーム生成器

    128ビット鍵と64ビットIVから暗号ストリームを生成します。
    """

    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        """
        RabbitStreamGeneratorを初期化

        Args:
            key: 16バイト（128ビット）の鍵
            iv: 8バイト（64ビット）の初期化ベクトル（省略可）

        Raises:
            ValueError: 鍵またはIVのサイズが不正な場合
        """
        if len(key) != KEY_SIZE_BYTES:
            raise ValueError(f"鍵は{KEY_SIZE_BYTES}バイトである必要があります")

        if iv is not None and len(iv) != IV_SIZE_BYTES:
            raise ValueError(f"IVは{IV_SIZE_BYTES}バイトである必要があります")

        # 内部状態（X）、カウンタ（C）、キャリービット（carry）を初期化
        self.X = [0] * RABBIT_STATE_SIZE  # 状態変数 X_0, ..., X_7
        self.C = [0] * RABBIT_COUNTER_SIZE  # カウンタ変数 C_0, ..., C_7
        self.carry = 0  # キャリービット

        # 鍵セットアップ
        self._key_setup(key)

        # IVがあれば、IV処理を行う
        if iv is not None:
            self._iv_setup(iv)

    def _key_setup(self, key: bytes) -> None:
        """
        鍵から内部状態を初期化（RFC 4503 セクション3.1）

        Args:
            key: 16バイト（128ビット）の鍵
        """
        # 鍵から16個の8ビット値（k_0, ..., k_15）を抽出
        k = list(key)

        # 鍵から8個の16ビット値（K_0, ..., K_7）を生成
        K = [0] * RABBIT_STATE_SIZE
        for i in range(RABBIT_STATE_SIZE):
            K[i] = (k[2*i+1] << 8) | k[2*i]

        # 内部状態の初期化
        for i in range(RABBIT_STATE_SIZE):
            if i % 2 == 0:
                self.X[i] = (K[(i+1) % 8] << 16) | K[i]
            else:
                self.X[i] = (K[(i+2) % 8] << 16) | K[(i+1) % 8]

        # カウンタ変数の初期化
        for i in range(RABBIT_COUNTER_SIZE):
            if i % 2 == 0:
                self.C[i] = (K[(i+4) % 8] << 16) | K[(i+5) % 8]
            else:
                self.C[i] = (K[(i+6) % 8] << 16) | K[(i+7) % 8]

        # キャリービットを0に初期化
        self.carry = 0

        # システムを4回イテレーション
        for _ in range(4):
            self._next_state()

    def _iv_setup(self, iv: bytes) -> None:
        """
        IVから内部状態を更新（RFC 4503 セクション3.2）

        Args:
            iv: 8バイト（64ビット）の初期化ベクトル
        """
        # IVから4個の16ビット値（I_0, ..., I_3）を生成
        I = [0] * 4
        for i in range(4):
            I[i] = (iv[2*i+1] << 8) | iv[2*i]

        # カウンタ変数を更新
        for i in range(RABBIT_COUNTER_SIZE):
            if i < 4:
                self.C[i] ^= (I[i % 4] << 16)
            else:
                self.C[i] ^= I[i % 4]

        # システムを4回イテレーション
        for _ in range(4):
            self._next_state()

    def _g_function(self, x: int) -> int:
        """
        RFC 4503のg関数（セクション2.3）

        Args:
            x: 32ビット入力値

        Returns:
            32ビット出力値
        """
        # x^2 + x mod 2^32 を計算
        x &= WORD_MASK  # 32ビットに制限
        square = (x * x) & 0xFFFFFFFFFFFFFFFF  # 64ビット積

        # 結果の下位32ビットと上位32ビットを加算
        result = (square & WORD_MASK) + ((square >> 32) & WORD_MASK)
        return result & WORD_MASK

    def _next_state(self) -> None:
        """
        内部状態を1ステップ更新（RFC 4503 セクション2.4）
        """
        # カウンタシステムの更新
        new_carry = 0
        for i in range(RABBIT_COUNTER_SIZE):
            temp = self.C[i] + A[i] + self.carry
            new_carry = temp >> 32
            self.C[i] = temp & WORD_MASK
            self.carry = new_carry

        # 状態変数の更新
        for i in range(RABBIT_STATE_SIZE):
            g_val = self._g_function(self.X[i] + self.C[i])

            if i == 0:
                self.X[0] = (g_val + ((self.X[7] << 16) + (self.X[6] >> 16))) & WORD_MASK
            elif i == 1:
                self.X[1] = (g_val + ((self.X[0] << 8) + (self.X[7] >> 24))) & WORD_MASK
            elif i == 2:
                self.X[2] = (g_val + ((self.X[1] << 16) + (self.X[0] >> 16))) & WORD_MASK
            elif i == 3:
                self.X[3] = (g_val + ((self.X[2] << 8) + (self.X[1] >> 24))) & WORD_MASK
            elif i == 4:
                self.X[4] = (g_val + ((self.X[3] << 16) + (self.X[2] >> 16))) & WORD_MASK
            elif i == 5:
                self.X[5] = (g_val + ((self.X[4] << 8) + (self.X[3] >> 24))) & WORD_MASK
            elif i == 6:
                self.X[6] = (g_val + ((self.X[5] << 16) + (self.X[4] >> 16))) & WORD_MASK
            elif i == 7:
                self.X[7] = (g_val + ((self.X[6] << 8) + (self.X[5] >> 24))) & WORD_MASK

    def _extract(self) -> bytes:
        """
        現在の内部状態から16バイトの出力ブロックを抽出（RFC 4503 セクション2.6）

        Returns:
            16バイトの出力ブロック
        """
        result = bytearray(RABBIT_OUTPUT_SIZE)

        # 状態から出力を計算
        S = [0] * RABBIT_STATE_SIZE
        for i in range(RABBIT_STATE_SIZE):
            if i % 2 == 0:
                S[i] = self.X[(i+1) % 8] ^ (self.X[i] >> 16)
            else:
                S[i] = self.X[(i+2) % 8] ^ (self.X[i] << 16)

        # バイトに変換
        for i in range(RABBIT_OUTPUT_SIZE):
            idx = i // 2
            if i % 2 == 0:
                result[i] = S[idx] & 0xFF
            else:
                result[i] = (S[idx] >> 8) & 0xFF

        return bytes(result)

    def generate(self, length: int) -> bytes:
        """
        指定された長さのストリーム鍵を生成

        Args:
            length: 生成するストリーム鍵の長さ（バイト単位）

        Returns:
            指定された長さのストリーム鍵
        """
        result = bytearray()

        # 必要なブロック数を計算
        blocks_needed = (length + RABBIT_OUTPUT_SIZE - 1) // RABBIT_OUTPUT_SIZE

        for _ in range(blocks_needed):
            # 現在の状態から出力ブロックを抽出
            output_block = self._extract()
            result.extend(output_block)

            # 次の状態に更新
            self._next_state()

        # 必要なバイト数だけ返す
        return bytes(result[:length])
```

### 4. ユーティリティ関数の実装

鍵導出や複数ストリーム生成のためのユーティリティ関数を追加します：

```python
def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    パスワードから鍵とIVを導出する

    Args:
        password: パスワード文字列
        salt: ソルト（省略時はランダム生成）

    Returns:
        (key, iv): 16バイトの鍵と8バイトのIV
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # PBKDF2でパスワードから32バイトの値を導出（鍵16バイト + IV8バイト + 予備8バイト）
    key_material = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        KDF_ITERATIONS,
        dklen=32
    )

    # 鍵とIVに分割
    key = key_material[:KEY_SIZE_BYTES]
    iv = key_material[KEY_SIZE_BYTES:KEY_SIZE_BYTES + IV_SIZE_BYTES]

    return key, iv, salt


def generate_test_stream(key: bytes, iv: bytes, length: int = 64) -> bytes:
    """
    テスト用にストリームを生成しHEX形式で出力

    Args:
        key: 16バイトの鍵
        iv: 8バイトのIV
        length: 生成するストリームの長さ

    Returns:
        生成されたストリームのHEX文字列
    """
    generator = RabbitStreamGenerator(key, iv)
    stream = generator.generate(length)
    return binascii.hexlify(stream).decode('ascii')


# メイン関数（単体テスト用）
if __name__ == "__main__":
    # RFC 4503のテストベクトルを使用
    test_key = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(" ", ""))
    test_iv = bytes.fromhex("00 00 00 00 00 00 00 00".replace(" ", ""))

    # RFC 4503セクション6のテストケースに対応する出力を確認
    generator = RabbitStreamGenerator(test_key, test_iv)
    output = generator.generate(16)

    print("鍵：", binascii.hexlify(test_key).decode('ascii'))
    print("IV：", binascii.hexlify(test_iv).decode('ascii'))
    print("出力：", binascii.hexlify(output).decode('ascii'))

    # RFC 4503セクション6.1のテスト出力に対応
    expected = "eda81c7bb9d8f3512c6728b839368e9e"
    actual = binascii.hexlify(generator.generate(16)).decode('ascii')
    print("期待値：", expected)
    print("実際値：", actual)
    print("一致：", expected.lower() == actual.lower())
```

## ✅ 完了条件

- [ ] RFC 4503 に準拠した Rabbit ストリーム生成アルゴリズムが実装されている
- [ ] テストベクトルを使用して実装の正確性が検証されている
- [ ] パスワードから鍵と IV を導出する機能が実装されている
- [ ] ストリームを生成して暗号化に使用できる状態になっている
- [ ] コードが適切にコメント化され、型ヒントが追加されている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# スクリプトを直接実行してRFC 4503のテストベクトルをチェック
python -m method_6_rabbit.rabbit_stream

# 別の鍵とIVでもテストしてみる
python -c "import binascii; from method_6_rabbit.rabbit_stream import RabbitStreamGenerator; key = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF'); iv = bytes.fromhex('0123456789ABCDEF'); gen = RabbitStreamGenerator(key, iv); print(binascii.hexlify(gen.generate(32)).decode('ascii'))"
```

## ⏰ 想定実装時間

約 8 時間

## 📚 参考資料

- [RFC 4503 - Rabbit Stream Cipher](https://datatracker.ietf.org/doc/html/rfc4503)
- [eSTREAM: the ECRYPT Stream Cipher Project](https://www.ecrypt.eu.org/stream/)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/en/latest/)

## 💬 備考

- Rabbit アルゴリズムの実装は、RFC 4503 の仕様に正確に従ってください
- ビット演算操作が多いため、マスクと型変換に注意が必要です
- 大きな整数の乗算が必要なため、Python 3.x 以上で実装してください
- OpenSSL 等の既存ライブラリの使用は避け、純粋な Python での実装を行ってください（要件の理解と独自実装のため）

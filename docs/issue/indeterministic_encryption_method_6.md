# 不確定性転写暗号化方式 🎲 実装【子 Issue #6】：状態エントロピー注入機能

お兄様！不確定性転写暗号化方式の秘密をさらに強化する状態エントロピー注入機能を実装しましょう！これで暗号解析者も混乱するはずです ✨

## 📋 タスク概要

不確定性転写暗号化方式において重要な「状態エントロピー注入機能」を実装します。この機能は、暗号文に追加のエントロピー（ランダム性）を注入し、正規と非正規のデータパスを区別できないように混在させることで、静的・動的解析から保護する役割を持ちます。

## 🔧 実装内容

`method_10_indeterministic/entropy_injector.py` ファイルに、状態エントロピー注入機能を実装します。

### 主要な機能：

1. エントロピーソース生成
2. 擬似ランダム配列生成
3. エントロピープール管理
4. 状態依存エントロピー注入
5. 解析対策ノイズ付加
6. エントロピーマーカー埋め込み

## 💻 実装手順

### 1. 必要なライブラリのインポート

`entropy_injector.py` の先頭に以下を記述します：

```python
"""
不確定性転写暗号化方式 - 状態エントロピー注入モジュール

暗号文に追加のエントロピーを注入し、暗号解析を困難にします。
このモジュールは、静的解析や動的解析からの保護を強化します。
"""

import os
import time
import secrets
import hashlib
import hmac
import struct
import numpy as np
from typing import Dict, List, Tuple, Optional, Union, Any, Callable, ByteString

# 内部モジュールのインポート
from .config import (
    ENTROPY_POOL_SIZE,
    STATE_MATRIX_SIZE,
    KEY_SIZE_BYTES
)
```

### 2. エントロピープール管理クラスの実装

```python
class EntropyPool:
    """
    エントロピープールクラス

    乱数と擬似ランダム値のプールを管理し、暗号化プロセスに
    予測不可能性を注入するためのエントロピーを提供します。
    """

    def __init__(self, seed: bytes, size: int = ENTROPY_POOL_SIZE):
        """
        エントロピープールの初期化

        Args:
            seed: エントロピープールの初期シード
            size: プールのサイズ（バイト数）
        """
        self.seed = seed
        self.pool_size = size
        self.pool = bytearray(size)
        self.position = 0

        # プールの初期化
        self._initialize_pool()

    def _initialize_pool(self):
        """
        エントロピープールを初期化

        シードから決定論的に擬似ランダムなプールを生成します。
        実際の使用では、このプールにシステムの乱数ソースからの
        エントロピーも混合されます。
        """
        # 初期シードから擬似ランダムなプールを生成
        temp_pool = bytearray()
        current_seed = self.seed

        # プールサイズに達するまで擬似ランダムバイトを生成
        while len(temp_pool) < self.pool_size:
            # 現在のシードからハッシュを生成
            hash_bytes = hashlib.sha512(current_seed).digest()
            temp_pool.extend(hash_bytes)

            # 次のシードを更新
            current_seed = hash_bytes

        # プールサイズに切り詰め
        self.pool[:] = temp_pool[:self.pool_size]

        # システムのエントロピーソースから追加のエントロピーを注入
        self._add_system_entropy()

    def _add_system_entropy(self):
        """
        システムのエントロピーソースから追加のランダム性を注入
        """
        # システムの乱数ソースから追加のエントロピーを取得
        system_entropy = os.urandom(min(256, self.pool_size // 4))

        # 現在の時刻も利用
        time_bytes = struct.pack('!d', time.time())

        # プロセスID・スレッドID
        pid_bytes = struct.pack('!I', os.getpid())

        # すべてのエントロピーソースを結合
        entropy_sources = system_entropy + time_bytes + pid_bytes

        # プール全体にエントロピーを分散
        for i, byte in enumerate(entropy_sources):
            pos = (i * 53) % self.pool_size  # 素数でステップ
            self.pool[pos] ^= byte

        # プール全体をシャッフル
        self._mix_pool()

    def _mix_pool(self):
        """
        プール内のバイトを混合
        """
        # 現在のプール内容全体のハッシュを計算
        pool_hash = hashlib.sha256(self.pool).digest()

        # ハッシュを使ってプールを攪拌
        for i in range(8):
            # プールを8つのセクションに分割して個別に攪拌
            section_size = self.pool_size // 8
            section_start = i * section_size
            section_end = section_start + section_size

            # セクションにハッシュの影響を適用
            section_hash = hashlib.sha256(pool_hash + bytes([i])).digest()

            for j in range(section_start, min(section_end, self.pool_size)):
                hash_idx = (j - section_start) % len(section_hash)
                self.pool[j] ^= section_hash[hash_idx]

    def get_bytes(self, count: int) -> bytes:
        """
        プールから指定バイト数のデータを取得

        Args:
            count: 取得するバイト数

        Returns:
            エントロピープールからのランダムなバイト
        """
        result = bytearray(count)

        for i in range(count):
            # プール内の現在位置からバイトを取得
            result[i] = self.pool[self.position]

            # 位置を更新
            self.position = (self.position + 1) % self.pool_size

            # 定期的にプールを攪拌
            if self.position % 256 == 0:
                self._mix_pool()

        return bytes(result)

    def get_int(self, min_val: int = 0, max_val: int = 255) -> int:
        """
        指定範囲の整数を取得

        Args:
            min_val: 最小値
            max_val: 最大値

        Returns:
            min_val以上max_val以下の整数
        """
        if min_val > max_val:
            min_val, max_val = max_val, min_val

        # 必要なバイト数を計算
        range_size = max_val - min_val + 1
        byte_count = (range_size.bit_length() + 7) // 8
        byte_count = max(1, byte_count)

        # バイトを整数に変換
        while True:
            value_bytes = self.get_bytes(byte_count)
            value = int.from_bytes(value_bytes, byteorder='big')

            # 範囲内なら返す、そうでなければ再取得
            if value < range_size:
                return min_val + value

    def get_float(self, min_val: float = 0.0, max_val: float = 1.0) -> float:
        """
        指定範囲の浮動小数点数を取得

        Args:
            min_val: 最小値
            max_val: 最大値

        Returns:
            min_val以上max_val以下の浮動小数点数
        """
        # 8バイト取得
        float_bytes = self.get_bytes(8)

        # 0.0-1.0の浮動小数点数に変換
        integer = int.from_bytes(float_bytes, byteorder='big')
        normalized = integer / (2**(8*8) - 1)

        # 指定範囲にスケーリング
        return min_val + normalized * (max_val - min_val)

    def reseed(self, additional_seed: bytes):
        """
        プールに新しいシードを追加

        Args:
            additional_seed: 追加のシード
        """
        # 現在のプールとシードからハッシュを生成
        new_seed = hashlib.sha512(self.seed + additional_seed + bytes(self.pool)).digest()
        self.seed = new_seed

        # プールの一部を更新（完全な初期化は行わない）
        for i in range(0, self.pool_size, 64):
            section_hash = hashlib.sha512(new_seed + i.to_bytes(4, 'big')).digest()
            for j in range(min(64, self.pool_size - i)):
                self.pool[i + j] ^= section_hash[j]

        # プールを混合
        self._mix_pool()
```

### 3. エントロピー注入クラスの実装

```python
class EntropyInjector:
    """
    状態エントロピー注入クラス

    暗号化データに対して状態依存のエントロピーを注入し、
    解析による区別を困難にします。
    """

    def __init__(self, key: bytes, salt: Optional[bytes] = None):
        """
        エントロピー注入器の初期化

        Args:
            key: マスター鍵
            salt: ソルト値（省略時はランダム生成）
        """
        self.key = key
        self.salt = salt or os.urandom(16)

        # エントロピープールの初期化
        seed = hmac.new(self.key, b"entropy_pool" + self.salt, hashlib.sha256).digest()
        self.entropy_pool = EntropyPool(seed)

        # 内部状態変数
        self._injection_markers = self._generate_markers()
        self._injection_patterns = self._generate_patterns()

    def _generate_markers(self) -> List[bytes]:
        """
        エントロピー注入マーカーを生成

        マーカーは暗号化データの特定位置に埋め込まれ、
        復号時に暗号文の構造を識別するのに使用されます。

        Returns:
            マーカーバイト列のリスト
        """
        markers = []
        marker_seed = hmac.new(self.key, b"injection_markers" + self.salt, hashlib.sha256).digest()

        for i in range(8):  # 8つの異なるマーカーを生成
            marker = hmac.new(
                self.key,
                marker_seed + i.to_bytes(1, 'big'),
                hashlib.sha256
            ).digest()[:8]  # 8バイトのマーカー
            markers.append(marker)

        return markers

    def _generate_patterns(self) -> List[int]:
        """
        注入パターンを生成

        注入パターンは、暗号化データのどの位置にエントロピーを
        注入するかを決定します。

        Returns:
            注入パターンのリスト
        """
        pattern_count = 16
        patterns = []
        pattern_seed = hmac.new(self.key, b"injection_patterns" + self.salt, hashlib.sha256).digest()

        for i in range(pattern_count):
            pattern_hash = hmac.new(
                self.key,
                pattern_seed + i.to_bytes(1, 'big'),
                hashlib.sha256
            ).digest()

            # パターンの特性を決定
            density = pattern_hash[0] / 255.0  # 0.0-1.0
            offset = int.from_bytes(pattern_hash[1:3], byteorder='big') % 64
            step = (pattern_hash[3] % 63) + 1  # 1-64

            pattern = {
                "density": density,
                "offset": offset,
                "step": step
            }
            patterns.append(pattern)

        return patterns

    def _generate_entropy_block(self, size: int, seed: bytes) -> bytes:
        """
        エントロピーブロックを生成

        指定されたシードと内部状態に基づいて、ランダムな
        エントロピーブロックを生成します。

        Args:
            size: 生成するブロックのサイズ
            seed: 追加のシード値

        Returns:
            エントロピーブロック
        """
        # シードをプールに適用
        self.entropy_pool.reseed(seed)

        # 指定サイズのブロックを生成
        return self.entropy_pool.get_bytes(size)

    def _generate_noise_pattern(self, data: bytes, pattern_index: int) -> bytes:
        """
        ノイズパターンを生成

        特定のパターンに基づいてノイズを生成します。

        Args:
            data: 元データ
            pattern_index: 使用するパターンのインデックス

        Returns:
            ノイズパターン
        """
        pattern = self._injection_patterns[pattern_index % len(self._injection_patterns)]
        result = bytearray(len(data))

        # パターンの特性に基づいてノイズを生成
        offset = pattern["offset"]
        step = pattern["step"]
        density = pattern["density"]

        # 注入位置を計算
        positions = []
        for i in range(offset, len(data), step):
            if self.entropy_pool.get_float() < density:
                positions.append(i)

        # 注入位置にノイズを生成
        for pos in positions:
            if pos < len(result):
                noise_byte = self.entropy_pool.get_int(0, 255)
                result[pos] = noise_byte

        return bytes(result)

    def inject_entropy(
        self,
        true_data: bytes,
        false_data: bytes,
        mix_ratio: float = 0.3
    ) -> bytes:
        """
        暗号化データにエントロピーを注入

        true_dataとfalse_dataに対して、識別を困難にするための
        エントロピーを注入し、結果を返します。

        Args:
            true_data: 正規パスの暗号化データ
            false_data: 非正規パスの暗号化データ
            mix_ratio: 混合比率（0.0-1.0）

        Returns:
            エントロピー注入後のデータ
        """
        # シードの生成
        entropy_seed = hashlib.sha256(self.key + self.salt + b"entropy_injection").digest()

        # 基本エントロピーブロックの生成
        base_entropy = self._generate_entropy_block(1024, entropy_seed)

        # データハッシュの生成（データ検証用）
        true_hash = hashlib.sha256(true_data).digest()
        false_hash = hashlib.sha256(false_data).digest()

        # ランダムノイズの生成
        true_noise = self._generate_noise_pattern(true_data, 0)
        false_noise = self._generate_noise_pattern(false_data, 1)

        # 暗号文の構造マーカーを生成
        markers = self._injection_markers

        # 各コンポーネントを結合
        components = []

        # ベースエントロピー
        components.append(markers[0])
        components.append(base_entropy[:512])

        # true_dataのハッシュとノイズ
        components.append(markers[1])
        components.append(true_hash)
        components.append(markers[2])
        components.append(true_noise[:256])

        # false_dataのハッシュとノイズ
        components.append(markers[3])
        components.append(false_hash)
        components.append(markers[4])
        components.append(false_noise[:256])

        # カスタムエントロピーデータ
        custom_entropy = self._generate_confusion_data(true_data, false_data, mix_ratio)
        components.append(markers[5])
        components.append(custom_entropy)

        # 最終的なエントロピーデータ
        return b''.join(components)

    def _generate_confusion_data(
        self,
        true_data: bytes,
        false_data: bytes,
        mix_ratio: float
    ) -> bytes:
        """
        解析を困難にするための混合データを生成

        true_dataとfalse_dataを混合し、解析を困難にするための
        データを生成します。

        Args:
            true_data: 正規パスの暗号化データ
            false_data: 非正規パスの暗号化データ
            mix_ratio: 混合比率

        Returns:
            混合データ
        """
        # 混合データのサイズを決定
        size = min(512, min(len(true_data), len(false_data)) // 4)

        # 混合データの生成
        result = bytearray(size)

        for i in range(size):
            # 正規データと非正規データからバイトを選択
            true_idx = self.entropy_pool.get_int(0, len(true_data) - 1)
            false_idx = self.entropy_pool.get_int(0, len(false_data) - 1)

            # 混合比率に基づいて選択
            if self.entropy_pool.get_float() < mix_ratio:
                # 正規データと非正規データを混合
                result[i] = (true_data[true_idx] ^ false_data[false_idx]) & 0xFF
            else:
                # どちらかのデータを選択
                if self.entropy_pool.get_float() < 0.5:
                    result[i] = true_data[true_idx]
                else:
                    result[i] = false_data[false_idx]

            # 定期的にノイズを追加
            if i % 16 == 0:
                result[i] = self.entropy_pool.get_int(0, 255)

        return bytes(result)
```

### 4. ユーティリティ関数の実装

```python
def analyze_entropy(data: bytes) -> Dict[str, Any]:
    """
    データのエントロピー特性を分析

    Args:
        data: 分析するデータ

    Returns:
        エントロピー特性の辞書
    """
    if not data:
        return {"error": "空データ"}

    # バイト値の出現頻度を計算
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1

    # Shannon エントロピーの計算
    entropy = 0.0
    total_bytes = len(data)

    for count in counts.values():
        prob = count / total_bytes
        entropy -= prob * np.log2(prob)

    # ランダム性の指標
    byte_set = set(data)
    unique_ratio = len(byte_set) / 256  # ユニークバイトの割合

    return {
        "size": total_bytes,
        "entropy": entropy,
        "max_entropy": 8.0,  # 理論上の最大値
        "entropy_percent": (entropy / 8.0) * 100,
        "unique_bytes": len(byte_set),
        "unique_ratio": unique_ratio,
        "is_random": entropy > 7.5  # 経験的しきい値
    }


def create_injector(key: bytes, salt: Optional[bytes] = None) -> EntropyInjector:
    """
    エントロピー注入器を作成

    Args:
        key: マスター鍵
        salt: ソルト値（省略時はランダム生成）

    Returns:
        エントロピー注入器
    """
    return EntropyInjector(key, salt)


def inject_entropy_to_data(
    true_data: bytes,
    false_data: bytes,
    key: bytes,
    salt: Optional[bytes] = None,
    mix_ratio: float = 0.3
) -> bytes:
    """
    データにエントロピーを注入

    Args:
        true_data: 正規パスの暗号化データ
        false_data: 非正規パスの暗号化データ
        key: マスター鍵
        salt: ソルト値（省略時はランダム生成）
        mix_ratio: 混合比率

    Returns:
        エントロピー注入後のデータ
    """
    injector = create_injector(key, salt)
    return injector.inject_entropy(true_data, false_data, mix_ratio)
```

### 5. テスト用関数の実装

```python
def test_entropy_injection():
    """
    エントロピー注入のテスト関数
    """
    # テストデータの生成
    true_data = os.urandom(1024)
    false_data = os.urandom(1024)

    # テスト鍵の生成
    test_key = os.urandom(KEY_SIZE_BYTES)

    # エントロピー注入
    print("エントロピー注入を実行中...")
    entropy_data = inject_entropy_to_data(true_data, false_data, test_key)

    # 結果の解析
    print("\nエントロピー分析:")

    true_entropy = analyze_entropy(true_data)
    false_entropy = analyze_entropy(false_data)
    result_entropy = analyze_entropy(entropy_data)

    print(f"正規データ   : サイズ={true_entropy['size']}バイト, エントロピー={true_entropy['entropy']:.4f}")
    print(f"非正規データ : サイズ={false_entropy['size']}バイト, エントロピー={false_entropy['entropy']:.4f}")
    print(f"注入後データ : サイズ={result_entropy['size']}バイト, エントロピー={result_entropy['entropy']:.4f}")

    # 詳細分析
    if result_entropy["entropy"] > 7.8:
        print("✓ 高エントロピー（統計的解析に対する耐性が高い）")
    else:
        print("✗ 低エントロピー（統計的特徴が残っている可能性あり）")

    if result_entropy["unique_ratio"] > 0.9:
        print("✓ 高ユニーク率（バイト分布が均一）")
    else:
        print("✗ 低ユニーク率（特定のバイト値が偏っている可能性あり）")

    return entropy_data


# メイン関数
if __name__ == "__main__":
    test_entropy_injection()
```

## ✅ 完了条件

- [ ] エントロピープール（EntropyPool）クラスが実装されている
- [ ] エントロピー注入（EntropyInjector）クラスが実装されている
- [ ] エントロピープールの乱数生成関数（get_bytes, get_int, get_float）が実装されている
- [ ] マーカー生成とパターン生成機能が実装されている
- [ ] 混合データ生成機能が実装されている
- [ ] エントロピー分析関数が実装されている
- [ ] テスト関数が正常に動作し、高エントロピーの出力が生成されることが確認できる

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# モジュールを単体で実行してテスト
python -m method_10_indeterministic.entropy_injector

# エントロピー注入の検証
python -c "from method_10_indeterministic.entropy_injector import test_entropy_injection; test_entropy_injection()"
```

## ⏰ 想定実装時間

約 3 時間

## 📚 参考資料

- [情報エントロピーの概念](<https://en.wikipedia.org/wiki/Entropy_(information_theory)>)
- [擬似乱数生成器](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
- [暗号化におけるエントロピーの重要性](https://www.schneier.com/academic/archives/1996/01/measuring_the_streng.html)
- [NumPy ライブラリのドキュメント](https://numpy.org/doc/stable/)

## 💬 備考

- エントロピープール実装では、完全に予測不可能なランダム性を提供するため、システムの乱数ソースを積極的に活用してください
- 異なる環境での動作の一貫性を確保するために、決定論的な部分と非決定論的な部分のバランスに注意してください
- エントロピー注入はセキュリティを高めますが、データサイズが増加することに留意してください
- 復号時に必要な情報を適切にマーカーとして埋め込み、正確な復号が可能になるようにしてください
- テスト時には、エントロピーの質を客観的に評価するために、複数の異なる統計的テストを用いることを検討してください

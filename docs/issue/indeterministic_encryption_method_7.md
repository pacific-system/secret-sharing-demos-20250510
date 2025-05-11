# 不確定性転写暗号化方式 🎲 実装【子 Issue #7】：状態カプセル化機構

お兄様！不確定性転写暗号化方式の最後の秘密の要素、状態カプセル化機構を実装しましょう！真偽を見分けられない不思議な箱の完成です ✨

## 📋 タスク概要

不確定性転写暗号化方式において重要な「状態カプセル化機構」を実装します。この機能は、正規パスと非正規パスの暗号文を単一のカプセルにシームレスに統合し、解析者が二つの異なるパスの存在を検出できないようにします。

## 🔧 実装内容

`method_10_indeterministic/state_capsule.py` ファイルに、状態カプセル化機構を実装します。

### 主要な機能：

1. 状態カプセル生成
2. インターリーブマッピング
3. シャッフル暗号化
4. カプセル署名
5. データ配置の決定論的混合
6. カプセル解析支援（復号用）

## 💻 実装手順

### 1. 必要なライブラリのインポート

`state_capsule.py` の先頭に以下を記述します：

```python
"""
不確定性転写暗号化方式 - 状態カプセル化モジュール

正規パスと非正規パスの暗号文を単一のカプセルにシームレスに統合し、
解析や分離を困難にします。
"""

import os
import hashlib
import hmac
import struct
import secrets
import math
import numpy as np
from typing import Dict, List, Tuple, Optional, Union, Any, Callable, ByteString

# 内部モジュールのインポート
from .config import KEY_SIZE_BYTES
```

### 2. カプセル化ツールクラスの実装

```python
class StateCapsule:
    """
    状態カプセル化クラス

    正規パスと非正規パスの暗号文を、解析困難な単一のカプセルに
    統合します。このカプセルは、鍵に応じて異なる平文を復元可能にしながらも、
    静的・動的解析からの保護を提供します。
    """

    def __init__(self, key: bytes, salt: Optional[bytes] = None):
        """
        カプセル化機構の初期化

        Args:
            key: マスター鍵
            salt: ソルト値（省略時はランダム生成）
        """
        self.key = key
        self.salt = salt or os.urandom(16)

        # 混合機能用の内部状態
        self._shuffle_map = {}
        self._block_map = {}
        self._capsule_seed = hashlib.sha256(self.key + self.salt + b"state_capsule").digest()

    def _initialize_mappings(self, data_size: int, block_size: int = 64):
        """
        インターリーブ・シャッフルマッピングを初期化

        Args:
            data_size: 処理するデータのサイズ
            block_size: ブロックサイズ
        """
        # ブロックマッピングの初期化
        num_blocks = math.ceil(data_size / block_size)
        self._block_map = {}

        # 各ブロックの処理方法を決定
        for i in range(num_blocks):
            # ブロック処理方式の決定シード
            block_seed = hashlib.sha256(self._capsule_seed + f"block_{i}".encode()).digest()

            # ブロック処理タイプ (0-2) = [true→false, false→true, インターリーブ]
            block_type = block_seed[0] % 3

            # インターリーブの粒度（バイト単位or半分単位など）
            interleave_granularity = max(1, block_seed[1] % 8)  # 1-8バイト

            self._block_map[i] = {
                "type": block_type,
                "granularity": interleave_granularity
            }

        # シャッフルマッピングの初期化
        total_size = data_size * 2  # 正規＋非正規
        self._shuffle_map = {}
        available_positions = list(range(total_size))

        # シャッフルマップの生成
        for i in range(total_size):
            # 決定論的なシャッフル（鍵に依存）
            shuffle_seed = hashlib.sha256(self._capsule_seed + f"shuffle_{i}".encode()).digest()
            index = int.from_bytes(shuffle_seed[:4], byteorder='big') % len(available_positions)
            position = available_positions.pop(index)
            self._shuffle_map[i] = position

    def _create_block_interleave(
        self,
        true_block: bytes,
        false_block: bytes,
        block_info: Dict[str, Any]
    ) -> bytes:
        """
        ブロックインターリーブ処理

        二つのブロックを指定された方法で混合します。

        Args:
            true_block: 正規パスのブロック
            false_block: 非正規パスのブロック
            block_info: ブロック処理情報

        Returns:
            混合されたブロック
        """
        block_type = block_info["type"]

        # ブロック長の調整（短い方を0でパディング）
        max_len = max(len(true_block), len(false_block))
        if len(true_block) < max_len:
            true_block = true_block.ljust(max_len, b'\x00')
        if len(false_block) < max_len:
            false_block = false_block.ljust(max_len, b'\x00')

        # ブロック処理タイプに基づいて処理
        if block_type == 0:
            # 正規→非正規
            return true_block + false_block
        elif block_type == 1:
            # 非正規→正規
            return false_block + true_block
        else:
            # インターリーブ
            granularity = block_info["granularity"]
            result = bytearray()

            # 指定された粒度でインターリーブ
            for i in range(0, max_len, granularity):
                # 正規パスデータ
                for j in range(granularity):
                    if i + j < len(true_block):
                        result.append(true_block[i + j])

                # 非正規パスデータ
                for j in range(granularity):
                    if i + j < len(false_block):
                        result.append(false_block[i + j])

            return bytes(result)

    def _apply_shuffle(self, data: bytes) -> bytes:
        """
        シャッフル処理を適用

        Args:
            data: シャッフルするデータ

        Returns:
            シャッフルされたデータ
        """
        # シャッフル用の配列の初期化
        shuffled = bytearray(len(data))

        # シャッフルマップに従ってデータを配置
        for src, dst in self._shuffle_map.items():
            if src < len(data) and dst < len(shuffled):
                shuffled[dst] = data[src]

        return bytes(shuffled)

    def _pre_process_signature(self, signature: bytes) -> bytes:
        """
        署名データの前処理

        署名データを暗号化して保護します。

        Args:
            signature: 署名データ

        Returns:
            処理された署名データ
        """
        # 署名データのハッシュ化
        processed = hmac.new(
            self._capsule_seed,
            signature,
            hashlib.sha256
        ).digest()

        # 鍵依存の攪拌
        mixed = bytearray(len(processed))
        for i in range(len(processed)):
            # 鍵に依存したバイト変換
            key_byte = self.key[i % len(self.key)]
            salt_byte = self.salt[i % len(self.salt)]
            mixed[i] = (processed[i] ^ key_byte ^ salt_byte) & 0xFF

        return bytes(mixed)

    def create_capsule(
        self,
        true_data: bytes,
        false_data: bytes,
        true_signature: bytes,
        false_signature: bytes
    ) -> bytes:
        """
        暗号化データの状態カプセル化

        Args:
            true_data: 正規パスの暗号化データ
            false_data: 非正規パスの暗号化データ
            true_signature: 正規パスの署名
            false_signature: 非正規パスの署名

        Returns:
            カプセル化されたデータ
        """
        # ブロックサイズの決定
        block_size = 64

        # データをブロックに分割
        true_blocks = [true_data[i:i+block_size] for i in range(0, len(true_data), block_size)]
        false_blocks = [false_data[i:i+block_size] for i in range(0, len(false_data), block_size)]

        # ブロック数を揃える
        max_blocks = max(len(true_blocks), len(false_blocks))

        # 不足ブロックを追加
        if len(true_blocks) < max_blocks:
            for i in range(max_blocks - len(true_blocks)):
                seed = self._capsule_seed + f"true_padding_{i}".encode()
                dummy = hashlib.sha256(seed).digest()[:block_size]
                true_blocks.append(dummy)

        if len(false_blocks) < max_blocks:
            for i in range(max_blocks - len(false_blocks)):
                seed = self._capsule_seed + f"false_padding_{i}".encode()
                dummy = hashlib.sha256(seed).digest()[:block_size]
                false_blocks.append(dummy)

        # マッピングの初期化
        self._initialize_mappings(max_blocks * block_size, block_size)

        # 署名データの前処理
        true_sig_processed = self._pre_process_signature(true_signature)
        false_sig_processed = self._pre_process_signature(false_signature)

        # カプセル化データの初期化
        capsule = bytearray()

        # 署名データを埋め込み
        capsule.extend(true_sig_processed)
        capsule.extend(false_sig_processed)

        # ブロック処理
        for i in range(max_blocks):
            block_info = self._block_map.get(i, {"type": 0, "granularity": 1})
            mixed_block = self._create_block_interleave(true_blocks[i], false_blocks[i], block_info)
            capsule.extend(mixed_block)

        # カプセル全体にシャッフル適用
        shuffled_capsule = self._apply_shuffle(capsule)

        return shuffled_capsule
```

### 3. カプセル構造分析クラスの実装

```python
class CapsuleAnalyzer:
    """
    カプセル構造分析クラス

    カプセル化されたデータの内部構造を分析し、
    デバッグ・検証のための情報を提供します。
    """

    def __init__(self, key: bytes, salt: bytes):
        """
        分析器の初期化

        Args:
            key: マスター鍵
            salt: ソルト値
        """
        self.key = key
        self.salt = salt
        self.capsule_seed = hashlib.sha256(self.key + self.salt + b"state_capsule").digest()

    def analyze_capsule(self, capsule_data: bytes, block_size: int = 64) -> Dict[str, Any]:
        """
        カプセルを分析

        Args:
            capsule_data: 分析するカプセルデータ
            block_size: ブロックサイズ

        Returns:
            分析結果の辞書
        """
        # シャッフルマッピングの再構築
        shuffle_map = {}
        inverse_map = {}

        # カプセルの逆シャッフル用マッピングを生成
        available_positions = list(range(len(capsule_data)))

        for i in range(len(capsule_data)):
            # 決定論的なシャッフル（鍵に依存）
            shuffle_seed = hashlib.sha256(self.capsule_seed + f"shuffle_{i}".encode()).digest()
            index = int.from_bytes(shuffle_seed[:4], byteorder='big') % len(available_positions)
            position = available_positions.pop(index)
            shuffle_map[i] = position
            inverse_map[position] = i

        # ブロックマッピングの再構築
        data_size = (len(capsule_data) - 64) // 2  # 署名部分を除く
        num_blocks = math.ceil(data_size / block_size)
        block_map = {}

        for i in range(num_blocks):
            # ブロック処理方式の決定シード
            block_seed = hashlib.sha256(self.capsule_seed + f"block_{i}".encode()).digest()

            # ブロック処理タイプ
            block_type = block_seed[0] % 3

            # インターリーブの粒度
            interleave_granularity = max(1, block_seed[1] % 8)

            block_map[i] = {
                "type": block_type,
                "granularity": interleave_granularity
            }

        # 分析結果の集計
        analysis = {
            "capsule_size": len(capsule_data),
            "signature_size": 64,  # 2つの署名（32バイト x 2）
            "data_size": data_size,
            "num_blocks": num_blocks,
            "block_size": block_size,
            "blocks": {},
            "signature": {}
        }

        # ブロックタイプの分布
        type_distribution = {0: 0, 1: 0, 2: 0}

        for i, block_info in block_map.items():
            block_type = block_info["type"]
            type_distribution[block_type] += 1

            # 詳細なブロック情報を保存
            analysis["blocks"][i] = {
                "type": ["true→false", "false→true", "interleave"][block_type],
                "granularity": block_info["granularity"] if block_type == 2 else "N/A"
            }

        # 分布の割合を計算
        total_blocks = sum(type_distribution.values())
        analysis["type_distribution"] = {
            "true→false": f"{type_distribution[0] / total_blocks:.2%}",
            "false→true": f"{type_distribution[1] / total_blocks:.2%}",
            "interleave": f"{type_distribution[2] / total_blocks:.2%}"
        }

        # エントロピー分析
        counts = {}
        for byte in capsule_data:
            counts[byte] = counts.get(byte, 0) + 1

        entropy = 0.0
        for count in counts.values():
            prob = count / len(capsule_data)
            entropy -= prob * math.log2(prob)

        analysis["entropy"] = {
            "value": entropy,
            "max": 8.0,
            "percent": (entropy / 8.0) * 100,
            "unique_bytes": len(counts),
            "randomness": "高" if entropy > 7.5 else "中" if entropy > 7.0 else "低"
        }

        return analysis
```

### 4. ユーティリティ関数の実装

```python
def create_state_capsule(
    true_data: bytes,
    false_data: bytes,
    true_signature: bytes,
    false_signature: bytes,
    key: bytes,
    salt: Optional[bytes] = None
) -> bytes:
    """
    状態カプセルを作成

    Args:
        true_data: 正規パスの暗号化データ
        false_data: 非正規パスの暗号化データ
        true_signature: 正規パスの署名
        false_signature: 非正規パスの署名
        key: マスター鍵
        salt: ソルト値（省略時はランダム生成）

    Returns:
        カプセル化されたデータ
    """
    capsule = StateCapsule(key, salt)
    return capsule.create_capsule(true_data, false_data, true_signature, false_signature)


def extract_from_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    path_type: str
) -> bytes:
    """
    カプセルから特定のパスのデータを抽出

    Args:
        capsule_data: カプセル化されたデータ
        key: 復号鍵
        salt: ソルト値
        path_type: パスタイプ ("true" または "false")

    Returns:
        抽出されたデータ
    """
    # カプセル化パラメータのシード値
    capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()

    # データブロックサイズの決定
    block_size = 64

    # カプセルの逆シャッフル
    # カプセル化時と同じシャッフルパターンを再現
    unshuffled_capsule = bytearray(len(capsule_data))
    shuffle_map = {}
    available_positions = list(range(len(capsule_data)))

    for i in range(len(capsule_data)):
        # 決定論的なシャッフル（鍵に依存）
        shuffle_seed = hashlib.sha256(capsule_seed + f"shuffle_{i}".encode()).digest()
        index = int.from_bytes(shuffle_seed[:4], byteorder='big') % len(available_positions)
        position = available_positions.pop(index)
        shuffle_map[i] = position

    # 逆シャッフルマップの作成
    inverse_map = {dst: src for src, dst in shuffle_map.items()}

    # シャッフルの復元
    for dst, src in inverse_map.items():
        if src < len(capsule_data) and dst < len(unshuffled_capsule):
            unshuffled_capsule[dst] = capsule_data[src]

    # 署名データを除去（最初の64バイト）
    data_part = unshuffled_capsule[64:]

    # パスタイプに基づくオフセット
    path_offset = 0 if path_type.lower() == "true" else 1

    # ブロックマッピングの再構築
    data_size = len(data_part) // 2  # 両方のパスデータが含まれている
    num_blocks = math.ceil(data_size / block_size)

    # ブロックごとにデータを抽出
    extracted_blocks = []
    pos = 0

    for i in range(num_blocks):
        # ブロック処理方式の決定シード
        block_seed = hashlib.sha256(capsule_seed + f"block_{i}".encode()).digest()

        # ブロック処理タイプ
        block_type = block_seed[0] % 3

        # インターリーブの粒度
        interleave_granularity = max(1, block_seed[1] % 8)

        # 現在位置のブロックサイズを計算
        remaining = len(data_part) - pos
        current_block_size = min(block_size * 2, remaining)

        # 残りのデータが少なすぎる場合は終了
        if current_block_size <= 0:
            break

        # ブロックの処理方法に基づいて抽出
        if block_type == 0:  # true→false
            # 正規パスならば前半、非正規パスならば後半
            start = pos if path_offset == 0 else pos + (current_block_size // 2)
            end = pos + (current_block_size // 2) if path_offset == 0 else pos + current_block_size
            extracted_blocks.append(data_part[start:end])

        elif block_type == 1:  # false→true
            # 正規パスならば後半、非正規パスならば前半
            start = pos + (current_block_size // 2) if path_offset == 0 else pos
            end = pos + current_block_size if path_offset == 0 else pos + (current_block_size // 2)
            extracted_blocks.append(data_part[start:end])

        else:  # interleave
            # インターリーブされたデータから特定のパスのデータを抽出
            extracted = bytearray()

            for j in range(0, current_block_size, interleave_granularity * 2):
                # 各パスのデータブロックの境界を計算
                start = j + (path_offset * interleave_granularity)
                end = start + interleave_granularity

                # 範囲チェック
                if pos + end <= len(data_part):
                    extracted.extend(data_part[pos + start:pos + end])

            extracted_blocks.append(bytes(extracted))

        # 次のブロック位置へ
        pos += current_block_size

    # 抽出したブロックを結合
    return b''.join(extracted_blocks)


def analyze_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes
) -> Dict[str, Any]:
    """
    カプセルを分析

    Args:
        capsule_data: カプセル化されたデータ
        key: マスター鍵
        salt: ソルト値

    Returns:
        分析結果
    """
    analyzer = CapsuleAnalyzer(key, salt)
    return analyzer.analyze_capsule(capsule_data)
```

### 5. テスト関数の実装

```python
def test_state_capsule():
    """
    状態カプセル化のテスト
    """
    # テストデータ
    true_data = os.urandom(1024)
    false_data = os.urandom(1024)

    # テスト署名
    true_signature = hashlib.sha256(b"true_path" + true_data).digest()
    false_signature = hashlib.sha256(b"false_path" + false_data).digest()

    # テスト鍵
    test_key = os.urandom(KEY_SIZE_BYTES)
    test_salt = os.urandom(16)

    print(f"テスト鍵: {test_key.hex()[:16]}...")
    print(f"テストソルト: {test_salt.hex()[:8]}...")

    # カプセル化
    print("\nカプセル化を実行中...")
    capsule = create_state_capsule(
        true_data,
        false_data,
        true_signature,
        false_signature,
        test_key,
        test_salt
    )

    print(f"カプセルサイズ: {len(capsule)} バイト")

    # カプセル分析
    print("\nカプセル構造分析:")
    analysis = analyze_capsule(capsule, test_key, test_salt)

    print(f"エントロピー: {analysis['entropy']['value']:.4f} ({analysis['entropy']['percent']:.2f}%)")
    print(f"ブロック数: {analysis['num_blocks']}")
    print("ブロックタイプ分布:")
    for type_name, percentage in analysis["type_distribution"].items():
        print(f"  - {type_name}: {percentage}")

    # 抽出テスト
    print("\n抽出テスト:")

    # 正規パスの抽出
    true_extracted = extract_from_capsule(capsule, test_key, test_salt, "true")
    true_match = true_data[:len(true_extracted)] == true_extracted[:len(true_data)]

    # 非正規パスの抽出
    false_extracted = extract_from_capsule(capsule, test_key, test_salt, "false")
    false_match = false_data[:len(false_extracted)] == false_extracted[:len(false_data)]

    print(f"正規パス抽出: {'成功' if true_match else '失敗'}")
    print(f"非正規パス抽出: {'成功' if false_match else '失敗'}")

    # 抽出データのサイズチェック
    print(f"正規抽出サイズ: {len(true_extracted)} バイト")
    print(f"非正規抽出サイズ: {len(false_extracted)} バイト")

    return capsule, true_extracted, false_extracted


# メイン関数
if __name__ == "__main__":
    test_state_capsule()
```

## ✅ 完了条件

- [ ] 状態カプセル化クラス（StateCapsule）が実装されている
- [ ] カプセル構造分析クラス（CapsuleAnalyzer）が実装されている
- [ ] カプセル化・抽出機能の実装が完了している
- [ ] 複数のブロック処理タイプ（順次配置、インターリーブ）が実装されている
- [ ] シャッフル機能が正常に動作している
- [ ] テスト関数が正常に動作し、以下が確認できる：
  - [ ] カプセル化 → 抽出で元データが復元できる
  - [ ] カプセルの分析結果が取得できる
  - [ ] エントロピーが高く、統計的解析が困難である

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# モジュールを単体で実行してテスト
python -m method_10_indeterministic.state_capsule

# カプセル化・抽出の検証
python -c "from method_10_indeterministic.state_capsule import test_state_capsule; test_state_capsule()"
```

## ⏰ 想定実装時間

約 4 時間

## 📚 参考資料

- [暗号化データのカプセル化技術](<https://en.wikipedia.org/wiki/Encapsulation_(computer_programming)>)
- [シャッフル暗号化手法](https://en.wikipedia.org/wiki/Permutation_cipher)
- [インターリーブ技術](https://en.wikipedia.org/wiki/Interleaving)
- [HMAC を用いた認証](https://en.wikipedia.org/wiki/HMAC)

## 💬 備考

- カプセル化処理は、暗号化された状態で行われることに注意してください
- 抽出処理は、復号時に使用されるため、特に効率的に実装する必要があります
- カプセル化されたデータのサイズは、元のデータサイズの約 2 倍になります
- ブロック処理タイプの分布は、ランダムに見えながも決定論的（鍵依存）である必要があります
- シャッフル機能が強力であるほど、静的解析に対する耐性が高まります

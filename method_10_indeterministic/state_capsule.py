"""
不確定性転写暗号化方式 - 状態カプセル化モジュール

正規パスと非正規パスの暗号文を単一のカプセルにシームレスに統合し、
解析や分離を困難にします。動的解析・静的解析への耐性を提供します。
"""

import os
import hashlib
import hmac
import struct
import secrets
import random
import time
import math
import tempfile
import json
import datetime
import numpy as np
from typing import Dict, List, Tuple, Optional, Union, Any, Callable, ByteString, Generator, BinaryIO

# 内部モジュールのインポート
try:
    from config import KEY_SIZE_BYTES, MIN_ENTROPY
except ImportError:
    # テスト用にモジュールが直接実行された場合のフォールバック
    KEY_SIZE_BYTES = 32
    MIN_ENTROPY = 7.0

# バッファサイズの設定 (8MB)
BUFFER_SIZE = 8 * 1024 * 1024

# 一時ファイルの最大サイズ (512MB)
MAX_TEMP_FILE_SIZE = 512 * 1024 * 1024

# カプセル化方式のバージョン
CAPSULE_VERSION = "1.0.0"

# 解析耐性レベル定義
class AnalysisResistanceLevel:
    LOW = 1      # 基本的な解析耐性
    MEDIUM = 2   # 中程度の解析耐性
    HIGH = 3     # 高度な解析耐性
    EXTREME = 4  # 極度の解析耐性（パフォーマンス低下の可能性あり）


class StateCapsule:
    """
    状態カプセル化クラス

    正規パスと非正規パスの暗号文を、解析困難な単一のカプセルに
    統合します。このカプセルは、鍵に応じて異なる平文を復元可能にしながらも、
    静的・動的解析からの保護を提供します。
    メモリ効率が良く、大規模なファイルも処理できます。
    """

    def __init__(self, key: bytes, salt: Optional[bytes] = None, resistance_level: int = AnalysisResistanceLevel.MEDIUM):
        """
        カプセル化機構の初期化

        Args:
            key: マスター鍵
            salt: ソルト値（省略時はランダム生成）
            resistance_level: 解析耐性レベル
        """
        self.key = key
        self.salt = salt or os.urandom(16)
        self.resistance_level = resistance_level

        # エントロピー強化（解析対策）
        timestamp = int(time.time() * 1000).to_bytes(8, 'big')
        enhanced_salt = hashlib.sha256(self.salt + timestamp).digest()
        self.enhanced_salt = enhanced_salt

        # 混合機能用の内部状態
        self._shuffle_map = {}
        self._block_map = {}
        self._capsule_seed = hashlib.sha256(self.key + self.salt + b"state_capsule").digest()

        # 内部トレース攪乱用のノイズ値
        self._noise_values = []
        for i in range(32):
            self._noise_values.append(os.urandom(16))

        # 解析対策用のダミー機能
        self._anti_analysis_init()

        # シャッフルマップの初期化
        self._initialize_shuffle_map()

        # ブロックマップの初期化
        self._initialize_block_map()

    def _anti_analysis_init(self):
        """解析対策のための初期化処理"""
        # 解析妨害用のデコイオブジェクト
        self._decoys = {}

        # ダミーの内部状態（解析困難化）
        dummy_count = 4 + self.resistance_level * 2
        for i in range(dummy_count):
            dummy_name = f"_internal_state_{secrets.token_hex(4)}"
            dummy_value = os.urandom(16)
            setattr(self, dummy_name, dummy_value)
            self._decoys[dummy_name] = dummy_value

        # 実行痕跡を残すダミー処理
        self._dummy_operations()

    def _dummy_operations(self):
        """解析時に混乱させるためのダミー処理"""
        # 解析時に意味のある処理に見えるようなダミー処理
        dummy_data = []
        for i in range(8):
            dummy_data.append(hashlib.sha256(self._noise_values[i % len(self._noise_values)]).digest())

        # ダミーの計算処理
        dummy_hash = hashlib.sha512(b''.join(dummy_data)).digest()
        dummy_result = int.from_bytes(dummy_hash[:8], 'big')

        # 使用されないがデコンパイル時に見えるダミー変数
        self._dummy_var1 = dummy_result % 256
        self._dummy_var2 = (dummy_result >> 8) % 256

        # デバッガ検出
        try:
            import sys
            # デバッガの存在をチェック（シンプルな方法）
            is_debugged = sys.gettrace() is not None
            if is_debugged and self.resistance_level >= AnalysisResistanceLevel.HIGH:
                # デバッガが検出された場合、動作を変える（ただし完全に壊さない）
                self._apply_anti_debug_measures()
        except:
            pass

    def _apply_anti_debug_measures(self):
        """デバッガが検出された場合の対応策"""
        # デバッガを検出した場合、内部動作を変更して解析を困難にする
        # ただし完全に機能を停止させるのではなく、解析を難しくする程度に

        # シャッフルアルゴリズムを変更
        self._shuffle_complexity = max(2, self.resistance_level)

        # ランダム性を強化
        self.salt = hashlib.sha256(self.salt + os.urandom(16)).digest()[:16]
        self._capsule_seed = hashlib.sha512(self._capsule_seed + os.urandom(32)).digest()

        # ブロックサイズをランダム化
        self._block_size_modifier = random.randint(1, 4)

    def _initialize_shuffle_map(self) -> None:
        """シャッフルマップを初期化する"""
        # 初期サイズを4KB程度に設定
        initial_size = 4096

        # エントロピープールを使用してシャッフルマップを生成
        shuffle_seed = hashlib.sha256(self._capsule_seed + b"shuffle_map").digest()
        rng = random.Random(shuffle_seed)

        # 初期マッピング（同一マッピング）
        indices = list(range(initial_size))

        # 解析耐性レベルに応じてシャッフルの強度を変える
        if self.resistance_level >= AnalysisResistanceLevel.MEDIUM:
            # 完全シャッフル
            rng.shuffle(indices)
        else:
            # 部分シャッフル（特定のパターンを維持）
            for i in range(0, initial_size, 64):
                end = min(i + 64, initial_size)
                segment = indices[i:end]
                rng.shuffle(segment)
                indices[i:end] = segment

        # シャッフルマップの作成
        self._shuffle_map = {src: dst for src, dst in enumerate(indices)}

    def _expand_shuffle_map(self, size: int) -> None:
        """
        シャッフルマップを指定サイズに拡張する

        Args:
            size: 拡張後のサイズ
        """
        current_size = max(self._shuffle_map.keys()) + 1
        if size <= current_size:
            return

        # 新しいインデックスのリスト
        new_indices = list(range(current_size, size))

        # 乱数シードは既存のシャッフルマップに依存
        seed_material = b''.join([
            self._capsule_seed,
            b"expand_shuffle",
            str(current_size).encode(),
            str(size).encode()
        ])
        expand_seed = hashlib.sha256(seed_material).digest()
        rng = random.Random(expand_seed)

        # シャッフル
        rng.shuffle(new_indices)

        # マップに追加
        for i, idx in enumerate(new_indices):
            src = current_size + i
            dst = current_size + idx - current_size
            self._shuffle_map[src] = dst

    def _initialize_block_map(self) -> None:
        """ブロックマップを初期化する"""
        # ブロック処理タイプを決定する乱数シード
        block_seed = hashlib.sha256(self._capsule_seed + b"block_map").digest()
        rng = random.Random(block_seed)

        # 初期ブロック数（16KB分のブロック）
        initial_blocks = 256

        # 解析耐性レベルに応じて、ブロック処理タイプの分布を決定
        type_distribution = {}
        granularity_range = {}

        if self.resistance_level == AnalysisResistanceLevel.LOW:
            # 低耐性: 順次配置が主体
            type_distribution = {0: 0.7, 1: 0.25, 2: 0.05}
            granularity_range = (1, 2)
        elif self.resistance_level == AnalysisResistanceLevel.MEDIUM:
            # 中耐性: バランスの取れた分布
            type_distribution = {0: 0.4, 1: 0.3, 2: 0.3}
            granularity_range = (1, 4)
        else:
            # 高耐性: インターリーブ配置が主体
            type_distribution = {0: 0.2, 1: 0.2, 2: 0.6}
            granularity_range = (1, 8)

        # ブロックごとに処理タイプを決定
        for i in range(initial_blocks):
            # タイプの選択
            r = rng.random()
            block_type = 0  # デフォルト

            cumulative = 0
            for t, prob in type_distribution.items():
                cumulative += prob
                if r <= cumulative:
                    block_type = t
                    break

            # インターリーブの場合は粒度も決定
            granularity = 1
            if block_type == 2:
                granularity = rng.randint(*granularity_range)

            # ブロックマップに追加
            self._block_map[i] = {
                "type": block_type,
                "granularity": granularity
            }

    def create_capsule(self, true_data: bytes, false_data: bytes,
                      true_signature: bytes, false_signature: bytes) -> bytes:
        """
        正規パスと非正規パスのデータをカプセル化

        Args:
            true_data: 正規パスのデータ
            false_data: 非正規パスのデータ
            true_signature: 正規データの署名
            false_signature: 非正規データの署名

        Returns:
            カプセル化されたデータ
        """
        # 大規模データの判定
        large_data = (len(true_data) > MAX_TEMP_FILE_SIZE or
                     len(false_data) > MAX_TEMP_FILE_SIZE)

        if large_data:
            return self._create_large_capsule(true_data, false_data,
                                            true_signature, false_signature)

        # 通常サイズのデータ処理
        return self._create_normal_capsule(true_data, false_data,
                                          true_signature, false_signature)

    def _create_normal_capsule(self, true_data: bytes, false_data: bytes,
                              true_signature: bytes, false_signature: bytes) -> bytes:
        """
        通常サイズのデータをカプセル化

        Args:
            true_data: 正規パスのデータ
            false_data: 非正規パスのデータ
            true_signature: 正規データの署名
            false_signature: 非正規データの署名

        Returns:
            カプセル化されたデータ
        """
        # ブロックサイズの決定
        block_size = 64

        # 署名の保護処理
        protected_true_signature = self._protect_signature(true_signature)
        protected_false_signature = self._protect_signature(false_signature)

        # 署名部分の準備（最初の署名ブロック）
        signature_part = protected_true_signature + protected_false_signature

        # データ部分の準備
        true_blocks = [true_data[i:i+block_size] for i in range(0, len(true_data), block_size)]
        false_blocks = [false_data[i:i+block_size] for i in range(0, len(false_data), block_size)]

        # 短い方のデータにパディングを追加
        max_blocks = max(len(true_blocks), len(false_blocks))

        if len(true_blocks) < max_blocks:
            # 正規データが短い場合はパディング
            padding_size = max_blocks - len(true_blocks)
            for i in range(padding_size):
                # パディングはランダムデータ
                true_blocks.append(os.urandom(block_size))

        if len(false_blocks) < max_blocks:
            # 非正規データが短い場合はパディング
            padding_size = max_blocks - len(false_blocks)
            for i in range(padding_size):
                # パディングはランダムデータ
                false_blocks.append(os.urandom(block_size))

        # 最後のブロックがブロックサイズより小さい場合はパディング
        if true_blocks and len(true_blocks[-1]) < block_size:
            pad_size = block_size - len(true_blocks[-1])
            true_blocks[-1] = true_blocks[-1] + os.urandom(pad_size)

        if false_blocks and len(false_blocks[-1]) < block_size:
            pad_size = block_size - len(false_blocks[-1])
            false_blocks[-1] = false_blocks[-1] + os.urandom(pad_size)

        # 混合データブロックの構築
        mixed_blocks = []

        for i in range(max_blocks):
            block_info = self._block_map.get(i, {"type": 0, "granularity": 1})
            true_block = true_blocks[i]
            false_block = false_blocks[i]

            # ブロックタイプに基づいて混合方法を選択
            if block_info["type"] == 0:
                # 順次配置 (true, false)
                mixed_blocks.append(true_block)
                mixed_blocks.append(false_block)
            elif block_info["type"] == 1:
                # 順次配置 (false, true)
                mixed_blocks.append(false_block)
                mixed_blocks.append(true_block)
            else:
                # インターリーブ配置
                granularity = block_info.get("granularity", 1)
                mixed_block = self._interleave_blocks(true_block, false_block, granularity)
                mixed_blocks.append(mixed_block)

        # カプセルデータの構築
        capsule_data = signature_part + b''.join(mixed_blocks)

        # シャッフル適用
        shuffled_data = self._apply_shuffle(capsule_data)

        return shuffled_data

    def _create_large_capsule(self, true_data: bytes, false_data: bytes,
                             true_signature: bytes, false_signature: bytes) -> bytes:
        """
        大規模データをカプセル化

        メモリ効率の良い実装で大容量ファイルを処理します。

        Args:
            true_data: 正規パスのデータ
            false_data: 非正規パスのデータ
            true_signature: 正規データの署名
            false_signature: 非正規データの署名

        Returns:
            カプセル化されたデータ
        """
        # 一時ファイルを使用
        temp_files = []

        try:
            # 署名の保護処理
            protected_true_signature = self._protect_signature(true_signature)
            protected_false_signature = self._protect_signature(false_signature)

            # 署名部分
            signature_part = protected_true_signature + protected_false_signature

            # 一時ファイルの作成
            temp_true = tempfile.NamedTemporaryFile(delete=False)
            temp_files.append(temp_true.name)
            temp_true.write(true_data)
            temp_true.close()

            temp_false = tempfile.NamedTemporaryFile(delete=False)
            temp_files.append(temp_false.name)
            temp_false.write(false_data)
            temp_false.close()

            # 出力用の一時ファイル
            temp_output = tempfile.NamedTemporaryFile(delete=False)
            temp_files.append(temp_output.name)

            # 署名部分を出力
            temp_output.write(signature_part)

            # ブロックサイズの設定
            block_size = 64
            buffer_size = 1024 * 1024  # 1MB

            # 両方のファイルからデータを読み込み、混合しながら出力
            with open(temp_true.name, 'rb') as true_file, \
                 open(temp_false.name, 'rb') as false_file:

                block_index = 0

                while True:
                    # 両方のファイルからブロックを読み込む
                    true_block = true_file.read(block_size)
                    false_block = false_file.read(block_size)

                    # どちらかのファイルの終了をチェック
                    if not true_block and not false_block:
                        break

                    # 最後のブロックがブロックサイズより小さい場合はパディング
                    if true_block and len(true_block) < block_size:
                        pad_size = block_size - len(true_block)
                        true_block = true_block + os.urandom(pad_size)

                    if false_block and len(false_block) < block_size:
                        pad_size = block_size - len(false_block)
                        false_block = false_block + os.urandom(pad_size)

                    # 一方のファイルが終了した場合は、ランダムデータで補完
                    if not true_block:
                        true_block = os.urandom(block_size)
                    if not false_block:
                        false_block = os.urandom(block_size)

                    # ブロックマップ情報を取得
                    block_info = self._block_map.get(block_index, {"type": 0, "granularity": 1})

                    # ブロックタイプに基づいて混合方法を選択
                    if block_info["type"] == 0:
                        # 順次配置 (true, false)
                        temp_output.write(true_block)
                        temp_output.write(false_block)
                    elif block_info["type"] == 1:
                        # 順次配置 (false, true)
                        temp_output.write(false_block)
                        temp_output.write(true_block)
                    else:
                        # インターリーブ配置
                        granularity = block_info.get("granularity", 1)
                        mixed_block = self._interleave_blocks(true_block, false_block, granularity)
                        temp_output.write(mixed_block)

                    block_index += 1

            temp_output.close()

            # シャッフル適用（ファイルベース）
            shuffled_output = tempfile.NamedTemporaryFile(delete=False)
            temp_files.append(shuffled_output.name)

            with open(temp_output.name, 'rb') as input_file, \
                 open(shuffled_output.name, 'wb') as output_file:

                # バッファ単位でシャッフル処理
                while True:
                    buffer_data = input_file.read(buffer_size)
                    if not buffer_data:
                        break

                    shuffled_buffer = self._apply_shuffle(buffer_data)
                    output_file.write(shuffled_buffer)

            # 最終結果の読み込み
            with open(shuffled_output.name, 'rb') as f:
                capsule_data = f.read()

            return capsule_data

        finally:
            # 一時ファイルの削除
            for file in temp_files:
                try:
                    if os.path.exists(file):
                        os.unlink(file)
                except Exception as e:
                    print(f"警告: 一時ファイル '{file}' の削除に失敗しました: {e}")

    def _protect_signature(self, signature: bytes) -> bytes:
        """
        署名を保護処理する

        改ざんを検出しやすくするため、チェックサムを追加します。

        Args:
            signature: 元の署名データ

        Returns:
            保護処理された署名
        """
        # 追加のチェックサム計算
        checksum = hashlib.md5(signature + self.salt).digest()

        # 署名データにチェックサムを付加
        protected = signature + checksum

        # 不足分をパディング（標準サイズに揃える）
        if len(protected) < 272:  # 署名(256) + チェックサム(16)
            padding_size = 272 - len(protected)
            protected = protected + os.urandom(padding_size)

        return protected

    def _interleave_blocks(self, true_block: bytes, false_block: bytes,
                          granularity: int = 1) -> bytes:
        """
        2つのブロックをインターリーブする

        Args:
            true_block: 正規パスのブロック
            false_block: 非正規パスのブロック
            granularity: 粒度（1=バイト単位、n=n バイト単位）

        Returns:
            インターリーブされたブロック
        """
        result = bytearray()

        # 粒度を制限（最大16バイト、最小1バイト）
        granularity = max(1, min(16, granularity))

        # 両方のブロックが同じサイズであることを確認
        min_len = min(len(true_block), len(false_block))
        true_part = true_block[:min_len]
        false_part = false_block[:min_len]

        # 粒度単位でインターリーブ
        for i in range(0, min_len, granularity):
            end_idx = min(i + granularity, min_len)
            result.extend(true_part[i:end_idx])
            result.extend(false_part[i:end_idx])

        # 両ブロックのサイズが異なる場合は、残りを追加
        if len(true_block) > min_len:
            result.extend(true_block[min_len:])

        if len(false_block) > min_len:
            result.extend(false_block[min_len:])

        return bytes(result)

    def _apply_shuffle(self, data: bytes) -> bytes:
        """
        シャッフルを適用する

        Args:
            data: シャッフルするデータ

        Returns:
            シャッフルされたデータ
        """
        # シャッフルマップがデータ長に対応していない場合は拡張
        if max(self._shuffle_map.keys(), default=0) < len(data) - 1:
            self._expand_shuffle_map(len(data))

        # データをコピーしてシャッフル
        data_array = bytearray(data)
        shuffled = bytearray(len(data))

        # シャッフルマップに従ってデータを配置
        for src, dst in self._shuffle_map.items():
            if src < len(data) and dst < len(data):
                shuffled[dst] = data_array[src]

        return bytes(shuffled)

    def _revert_signature(self, signature_data: bytes) -> bytes:
        """
        保護された署名から元の署名を取り出す

        Args:
            signature_data: 保護された署名データ

        Returns:
            元の署名
        """
        # 署名データの長さチェック
        if len(signature_data) < 272:  # 最小署名長: 署名(256) + チェックサム(16)
            raise ValueError("署名データが不正です")

        # 署名とチェックサムの分離
        signature = signature_data[:256]
        checksum = signature_data[256:272]

        # チェックサムを検証
        expected_checksum = hashlib.md5(signature + self.salt).digest()

        if checksum != expected_checksum:
            # チェックサム不一致（署名改ざんの可能性）
            print("警告: 署名のチェックサムが一致しません")
            # それでも署名は返す（上位層で対応）

        return signature

    def _extract_block_true(self, mixed_block: bytes, block_info: Dict) -> bytes:
        """
        混合ブロックから正規パスのデータを抽出

        Args:
            mixed_block: 混合されたブロック
            block_info: ブロック処理情報

        Returns:
            抽出されたデータ
        """
        block_type = block_info.get("type", 0)

        # ブロックタイプに基づいて抽出方法を選択
        if block_type == 0:
            # 順次配置 (true, false) の場合は前半部分を取得
            block_size = len(mixed_block) // 2
            return mixed_block[:block_size]
        elif block_type == 1:
            # 順次配置 (false, true) の場合は後半部分を取得
            block_size = len(mixed_block) // 2
            return mixed_block[block_size:]
        else:
            # インターリーブ配置の場合
            granularity = block_info.get("granularity", 1)
            return self._extract_interleaved_block(mixed_block, True, granularity)

    def _extract_block_false(self, mixed_block: bytes, block_info: Dict) -> bytes:
        """
        混合ブロックから非正規パスのデータを抽出

        Args:
            mixed_block: 混合されたブロック
            block_info: ブロック処理情報

        Returns:
            抽出されたデータ
        """
        block_type = block_info.get("type", 0)

        # ブロックタイプに基づいて抽出方法を選択
        if block_type == 0:
            # 順次配置 (true, false) の場合は後半部分を取得
            block_size = len(mixed_block) // 2
            return mixed_block[block_size:]
        elif block_type == 1:
            # 順次配置 (false, true) の場合は前半部分を取得
            block_size = len(mixed_block) // 2
            return mixed_block[:block_size]
        else:
            # インターリーブ配置の場合
            granularity = block_info.get("granularity", 1)
            return self._extract_interleaved_block(mixed_block, False, granularity)

    def _extract_interleaved_block(self, mixed_block: bytes, is_true_path: bool, granularity: int = 1) -> bytes:
        """
        インターリーブされたブロックからデータを抽出

        Args:
            mixed_block: インターリーブされたブロック
            is_true_path: True=正規パス、False=非正規パス
            granularity: 粒度（インターリーブの単位サイズ）

        Returns:
            抽出されたデータ
        """
        # 粒度を制限（最大16バイト、最小1バイト）
        granularity = max(1, min(16, granularity))

        # 結果バッファ
        result = bytearray()

        # ブロック長を粒度単位で計算
        units_count = len(mixed_block) // (granularity * 2)

        # インターリーブパターンから元のデータを抽出
        for i in range(units_count):
            start_idx = i * granularity * 2

            # 正規パスまたは非正規パスのどちらを取得するか
            if is_true_path:
                # 正規パスは最初のチャンク
                chunk_start = start_idx
            else:
                # 非正規パスは2番目のチャンク
                chunk_start = start_idx + granularity

            # 粒度分のデータを取得
            chunk_end = chunk_start + granularity
            if chunk_end <= len(mixed_block):
                result.extend(mixed_block[chunk_start:chunk_end])

        # 余りがあれば処理（最後の不完全なブロック）
        remaining = len(mixed_block) % (granularity * 2)
        if remaining > 0:
            last_start = units_count * granularity * 2

            if is_true_path and remaining > granularity:
                # 正規パスで余りが粒度より大きい場合
                result.extend(mixed_block[last_start:last_start+granularity])
            elif not is_true_path and remaining > granularity:
                # 非正規パスで余りが粒度より大きい場合
                result.extend(mixed_block[last_start+granularity:])
            elif is_true_path:
                # 正規パスで余りが粒度以下の場合
                result.extend(mixed_block[last_start:])

        return bytes(result)

    def extract_data(self, capsule_data: bytes, is_true_path: bool) -> Tuple[bytes, bytes]:
        """
        カプセル化データから指定パスのデータと署名を抽出

        Args:
            capsule_data: カプセル化されたデータ
            is_true_path: True=正規パス、False=非正規パス

        Returns:
            (抽出データ, 署名)のタプル
        """
        # カプセルデータから署名とデータを分離
        if len(capsule_data) < 544:  # 最小長: true_signature(272) + false_signature(272)
            # カプセルサイズが小さすぎる場合は空データを返す
            return b"", b""

        # 署名部分とデータ部分を分離
        signatures_part = capsule_data[:544]  # 署名部分
        data_part = capsule_data[544:]  # データ部分

        # シャッフル適用前の状態に戻す
        unshuffled_data = self._revert_shuffle(capsule_data)

        # シャッフル解除後も署名部分とデータ部分を再分離
        unshuffled_signatures = unshuffled_data[:544]
        unshuffled_data_part = unshuffled_data[544:]

        # 署名の抽出
        signature_offset = 0 if is_true_path else 272
        protected_signature = unshuffled_signatures[signature_offset:signature_offset+272]
        signature = self._revert_signature(protected_signature)

        # ブロックサイズの取得と確認
        block_size = 64

        # データブロックの分割
        blocks = []
        for i in range(0, len(unshuffled_data_part), block_size * 2):
            # ブロック終了インデックスの計算（境界チェック）
            end_idx = min(i + block_size * 2, len(unshuffled_data_part))

            # ブロック抽出
            if end_idx - i >= block_size:
                block = unshuffled_data_part[i:end_idx]
                blocks.append(block)

        # 抽出されたデータブロックの組み立て
        extracted_data = bytearray()

        for i, block in enumerate(blocks):
            # ブロック処理情報を取得
            block_info = self._block_map.get(i, {"type": 0, "granularity": 1})

            # 指定されたパス（正規または非正規）のデータを抽出
            if is_true_path:
                extracted_block = self._extract_block_true(block, block_info)
            else:
                extracted_block = self._extract_block_false(block, block_info)

            # 抽出されたデータを追加
            extracted_data.extend(extracted_block)

        return bytes(extracted_data), signature

    def _revert_shuffle(self, shuffled_data: bytes) -> bytes:
        """
        シャッフルを元に戻す

        Args:
            shuffled_data: シャッフルされたデータ

        Returns:
            元のデータ
        """
        # シャッフルマップがデータ長に対応していない場合は拡張
        if max(self._shuffle_map.keys(), default=0) < len(shuffled_data) - 1:
            self._expand_shuffle_map(len(shuffled_data))

        # シャッフルマップの逆マップを作成
        inverse_map = {dst: src for src, dst in self._shuffle_map.items()}

        # データをコピーしてシャッフル解除
        shuffled_array = bytearray(shuffled_data)
        unshuffled = bytearray(len(shuffled_data))

        # 逆マップに従ってデータを配置
        for dst, src in inverse_map.items():
            if src < len(shuffled_data) and dst < len(shuffled_data):
                unshuffled[src] = shuffled_array[dst]

        return bytes(unshuffled)


class CapsuleAnalyzer:
    """
    カプセル構造解析クラス

    カプセル化データの統計的特性や構造を解析し、情報を提供します。
    """

    def __init__(self, capsule: bytes = None):
        """
        解析器の初期化

        Args:
            capsule: 解析するカプセル（後から設定も可能）
        """
        self.capsule = capsule
        self.results = {}
        self.histogram = {}
        self._version = CAPSULE_VERSION
        self._analysis_timestamp = None

    def set_capsule(self, capsule: bytes):
        """
        解析対象のカプセルを設定

        Args:
            capsule: 解析するカプセル
        """
        self.capsule = capsule
        self.results = {}  # 結果をリセット
        self.histogram = {}

    def analyze(self) -> Dict:
        """
        カプセルの解析を実行

        複数の統計的特性を計算し、解析結果を保存します。

        Returns:
            解析結果の辞書
        """
        if not self.capsule:
            raise ValueError("解析対象のカプセルが設定されていません")

        # タイムスタンプを記録
        self._analysis_timestamp = datetime.datetime.now().isoformat()

        # 基本的な統計情報
        self._analyze_basic_statistics()

        # バイトの分布解析
        self._analyze_byte_distribution()

        # エントロピー計算
        self._calculate_entropy()

        # 自己相関解析
        self._analyze_autocorrelation()

        # 非ランダム性の兆候検出
        self._detect_non_randomness()

        # 解析結果をまとめる
        self.results["timestamp"] = self._analysis_timestamp
        self.results["version"] = self._version

        return self.results

    def _analyze_basic_statistics(self):
        """基本的な統計情報を解析"""
        data = self.capsule

        self.results["basic"] = {
            "size": len(data),
            "min": min(data) if data else 0,
            "max": max(data) if data else 0,
            "unique_bytes": len(set(data))
        }

    def _analyze_byte_distribution(self):
        """バイト値の分布を解析"""
        # ヒストグラム計算
        histogram = {}
        for b in range(256):
            histogram[b] = 0

        for byte in self.capsule:
            histogram[byte] += 1

        self.histogram = histogram

        # 分布の偏りを計算
        total_bytes = len(self.capsule)
        expected = total_bytes / 256  # 均等分布の期待値

        chi_square = 0
        if total_bytes > 0:
            for count in histogram.values():
                chi_square += ((count - expected) ** 2) / expected if expected > 0 else 0

        self.results["distribution"] = {
            "chi_square": chi_square,
            "p_value": self._calculate_chi_square_p_value(chi_square, 255),
            "histogram": histogram
        }

    def _calculate_chi_square_p_value(self, chi_square: float, df: int) -> float:
        """カイ二乗検定のp値（近似値）を計算"""
        # 簡易的な近似計算
        # 実際の実装では統計ライブラリを使用するとより正確
        k = df  # 自由度

        # 簡易近似（大きな自由度）
        z = math.sqrt(2 * chi_square) - math.sqrt(2 * k - 1)
        if z > 0:
            p_value = math.exp(-z * z / 2) / (z * math.sqrt(2 * math.pi))
            return min(p_value, 1.0)
        return 1.0

    def _calculate_entropy(self):
        """情報エントロピーの計算"""
        total = len(self.capsule)
        entropy = 0.0

        if total > 0:
            for count in self.histogram.values():
                if count > 0:
                    probability = count / total
                    entropy -= probability * math.log2(probability)

        # 最大エントロピーとの比較（8ビットのバイトなので最大は8）
        normalized_entropy = entropy / 8.0 if entropy > 0 else 0.0

        self.results["entropy"] = {
            "shannon": entropy,
            "normalized": normalized_entropy,
            "randomness_score": min(normalized_entropy * 10, 10.0)
        }

    def _analyze_autocorrelation(self):
        """自己相関解析"""
        data = self.capsule
        if len(data) < 100:
            self.results["autocorrelation"] = {"insufficient_data": True}
            return

        # シリアル相関係数（隣接バイト間）
        correlation = 0.0
        if len(data) > 1:
            # 先頭100バイトの相関を計算（計算コスト削減のため）
            sample = data[:min(5000, len(data))]
            pairs = list(zip(sample[:-1], sample[1:]))

            if pairs:
                correlation = sum(x[0] * x[1] for x in pairs) / len(pairs)
                # 正規化
                correlation = correlation / (127.5 * 127.5) - 1

        self.results["autocorrelation"] = {
            "serial_correlation": correlation,
            "independence_score": 10.0 * (1.0 - abs(correlation))
        }

    def _detect_non_randomness(self):
        """非ランダム性のパターンを検出"""
        data = self.capsule
        if len(data) < 100:
            self.results["patterns"] = {"insufficient_data": True}
            return

        # ラン検定（連の数）
        runs = 1
        for i in range(1, len(data)):
            if data[i] != data[i-1]:
                runs += 1

        expected_runs = (2 * len(data) - 1) / 3
        runs_score = min(10.0, 10.0 * runs / expected_runs) if expected_runs > 0 else 0.0

        # 反復パターンの検出（実際の実装ではより高度なアルゴリズムを使用）
        repeating_score = 10.0  # 初期値は高め

        # 簡易チェック: 連続する同一バイトの数
        same_byte_sequences = 0
        current_length = 1

        for i in range(1, len(data)):
            if data[i] == data[i-1]:
                current_length += 1
            else:
                if current_length > 3:  # 4バイト以上の連続を検出
                    same_byte_sequences += 1
                current_length = 1

        # 長い連続バイトがあると評価を下げる
        if same_byte_sequences > len(data) / 100:
            repeating_score -= min(5.0, same_byte_sequences / (len(data) / 100))

        self.results["patterns"] = {
            "runs": runs,
            "expected_runs": expected_runs,
            "runs_score": runs_score,
            "repeating_patterns_score": max(0.0, repeating_score)
        }

        # 総合スコア計算
        entropy_score = self.results["entropy"]["randomness_score"]
        independence_score = self.results["autocorrelation"]["independence_score"]
        pattern_score = self.results["patterns"]["repeating_patterns_score"]

        total_score = (entropy_score * 0.5) + (independence_score * 0.3) + (pattern_score * 0.2)

        self.results["overall"] = {
            "analysis_quality_score": min(10.0, total_score),
            "is_statistically_random": total_score > 7.0,
            "resistant_to_statistical_analysis": total_score > 8.5
        }

    def get_report(self, detailed: bool = False) -> Dict:
        """
        解析レポートを取得

        Args:
            detailed: 詳細レポートを含めるかのフラグ

        Returns:
            解析レポート
        """
        if not self.results:
            raise ValueError("解析が実行されていません。analyze()を先に呼び出してください。")

        if not detailed:
            # 簡易レポート（主要情報のみ）
            return {
                "timestamp": self.results["timestamp"],
                "version": self.results["version"],
                "size": self.results["basic"]["size"],
                "entropy": self.results["entropy"]["shannon"],
                "normalized_entropy": self.results["entropy"]["normalized"],
                "overall_score": self.results["overall"]["analysis_quality_score"],
                "is_statistically_random": self.results["overall"]["is_statistically_random"],
                "resistant_to_analysis": self.results["overall"]["resistant_to_statistical_analysis"]
            }

        # 詳細レポート
        return self.results

    def visualize_distribution(self) -> Dict:
        """
        バイト分布の可視化データを生成

        Returns:
            可視化用データ
        """
        if not self.histogram:
            raise ValueError("解析が実行されていません。analyze()を先に呼び出してください。")

        # バイトごとの出現頻度を正規化
        max_count = max(self.histogram.values()) if self.histogram else 1
        normalized = {k: v / max_count for k, v in self.histogram.items()}

        return {
            "type": "byte_distribution",
            "data": normalized,
            "max_count": max_count,
            "total_bytes": self.results["basic"]["size"] if "basic" in self.results else 0
        }

    def export_json(self, filepath: str = None, include_histogram: bool = False):
        """
        解析結果をJSONとして出力

        Args:
            filepath: 出力ファイルパス (None の場合は文字列として返す)
            include_histogram: ヒストグラムデータを含めるかのフラグ

        Returns:
            ファイルパスが None の場合は JSON 文字列
        """
        if not self.results:
            raise ValueError("解析が実行されていません。analyze()を先に呼び出してください。")

        # ヒストグラムは大きいため、フラグがオフの場合は除外
        export_data = self.results.copy()
        if not include_histogram and "distribution" in export_data:
            if "histogram" in export_data["distribution"]:
                export_data["distribution"] = export_data["distribution"].copy()
                del export_data["distribution"]["histogram"]

        # JSON変換
        json_data = json.dumps(export_data, indent=2)

        # ファイルに保存
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_data)
            return filepath

        return json_data


# テスト関数
def test_state_capsule():
    """
    状態カプセル化のテスト実行
    """
    try:
        print("状態カプセル化テストを開始")

        # テストデータ
        key = os.urandom(32)
        true_data = b"This is the true message. It should be revealed with the correct key."
        false_data = b"This is the false message. It should be revealed with the incorrect key."

        # 署名
        true_sig = hashlib.sha256(true_data).digest()
        false_sig = hashlib.sha256(false_data).digest()

        # カプセル化
        salt = os.urandom(16)
        resistance_level = AnalysisResistanceLevel.HIGH

        print(f"解析耐性レベル: {resistance_level}")

        capsule_obj = StateCapsule(key, salt, resistance_level)

        # カプセル化
        start_time = time.time()
        capsule_data = capsule_obj.create_capsule(true_data, false_data, true_sig, false_sig)
        duration = time.time() - start_time

        print(f"カプセル化完了: データサイズ {len(capsule_data)} バイト, 処理時間 {duration:.3f} 秒")

        # 解析
        analyzer = CapsuleAnalyzer(capsule_data)
        analysis = analyzer.analyze()

        print("解析結果:")
        print(f"- エントロピー: {analysis['entropy']['shannon']:.4f} ビット/バイト")
        print(f"- 正規化エントロピー: {analysis['entropy']['normalized']:.4f}")
        print(f"- 総合スコア: {analysis['overall']['analysis_quality_score']:.2f}/10.0")
        print(f"- 統計的ランダム性: {analysis['overall']['is_statistically_random']}")
        print(f"- 解析耐性: {analysis['overall']['resistant_to_statistical_analysis']}")

        # 正規パスでの抽出
        start_time = time.time()
        extracted_true, true_signature = capsule_obj.extract_data(capsule_data, True)
        duration = time.time() - start_time

        print(f"正規パスでの抽出完了: データサイズ {len(extracted_true)} バイト, 処理時間 {duration:.3f} 秒")
        print(f"正規データ一致: {extracted_true == true_data}")
        print(f"正規署名一致: {true_signature == true_sig}")

        # 非正規パスでの抽出
        start_time = time.time()
        extracted_false, false_signature = capsule_obj.extract_data(capsule_data, False)
        duration = time.time() - start_time

        print(f"非正規パスでの抽出完了: データサイズ {len(extracted_false)} バイト, 処理時間 {duration:.3f} 秒")
        print(f"非正規データ一致: {extracted_false == false_data}")
        print(f"非正規署名一致: {false_signature == false_sig}")

        return True

    except Exception as e:
        print(f"テスト実行中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    test_state_capsule()

class MemoryOptimizedReader:
    """
    メモリを効率的に使用するファイル読み込みクラス

    大きなファイルを分割してバッファリングして読み込み、メモリ使用量を最適化します。
    """

    def __init__(self, file_path: str, buffer_size: int = BUFFER_SIZE):
        """
        リーダーの初期化

        Args:
            file_path: 読み込むファイルのパス
            buffer_size: 読み込みバッファのサイズ
        """
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.file_size = os.path.getsize(file_path)
        self.temp_files = []
        self.fp = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self.cleanup()

    def open(self):
        """ファイルを開く"""
        if self.fp is None:
            try:
                self.fp = open(self.file_path, 'rb')
            except Exception as e:
                raise IOError(f"ファイル '{self.file_path}' を開けません: {e}")
        return self.fp

    def close(self):
        """ファイルを閉じる"""
        if self.fp is not None:
            try:
                self.fp.close()
                self.fp = None
            except Exception as e:
                print(f"警告: ファイルのクローズ中にエラーが発生しました: {e}")

    def read_in_chunks(self) -> Generator[bytes, None, None]:
        """
        ファイルを一定サイズのチャンクで読み込む

        Yields:
            ファイルデータのチャンク
        """
        fp = self.open()
        fp.seek(0)

        bytes_read = 0
        while bytes_read < self.file_size:
            # 読み込むチャンクサイズを計算（ファイル末尾の場合は残りサイズ）
            chunk_size = min(self.buffer_size, self.file_size - bytes_read)
            chunk = fp.read(chunk_size)
            if not chunk:
                break  # 予期せぬEOF

            bytes_read += len(chunk)
            yield chunk

    def read_all(self) -> bytes:
        """
        ファイル全体を読み込む

        大きなファイルの場合はメモリ効率を考慮した読み込みを行います。

        Returns:
            ファイルの内容
        """
        # 閾値を設定: この値より小さいファイルは直接読み込み
        small_file_threshold = 10 * 1024 * 1024  # 10MB

        # 小さいファイルの場合は直接読み込み
        if self.file_size <= small_file_threshold:
            fp = self.open()
            fp.seek(0)
            return fp.read()

        # 大きなファイルの場合は一時ファイル経由で処理
        with tempfile.NamedTemporaryFile(delete=False, prefix="capsule_temp_") as temp_file:
            self.temp_files.append(temp_file.name)

            # チャンクごとに読み込んで一時ファイルに書き込む
            for chunk in self.read_in_chunks():
                temp_file.write(chunk)

            temp_file.flush()

        # 一時ファイルからデータを読み込む
        try:
            with open(temp_file.name, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"警告: 一時ファイル読み込み中にエラーが発生しました: {e}")
            return b''  # エラー時は空データを返す

    def cleanup(self):
        """一時ファイルを削除"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}")


class MemoryOptimizedWriter:
    """
    メモリを効率的に使用するファイル書き込みクラス

    大きなデータを分割して書き込み、メモリ使用量を最適化します。
    """

    def __init__(self, file_path: str, buffer_size: int = BUFFER_SIZE):
        """
        ライターの初期化

        Args:
            file_path: 書き込むファイルのパス
            buffer_size: 書き込みバッファのサイズ
        """
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.temp_files = []
        self.fp = None
        self.bytes_written = 0
        self.is_open = False

        # 親ディレクトリが存在しない場合は作成
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except Exception as e:
                raise IOError(f"ディレクトリ '{parent_dir}' を作成できません: {e}")

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self.cleanup()

    def open(self):
        """ファイルを開く"""
        if self.fp is None:
            try:
                self.fp = open(self.file_path, 'wb')
                self.is_open = True
            except Exception as e:
                raise IOError(f"ファイル '{self.file_path}' を開けません: {e}")
        return self.fp

    def close(self):
        """ファイルを閉じる"""
        if self.fp is not None:
            try:
                self.fp.flush()
                self.fp.close()
                self.fp = None
                self.is_open = False
            except Exception as e:
                print(f"警告: ファイルのクローズ中にエラーが発生しました: {e}")

    def write(self, data: bytes) -> int:
        """
        データを書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if not data:
            return 0

        # 大きなデータを書き込む閾値
        large_data_threshold = 100 * 1024 * 1024  # 100MB

        # 小さいデータの場合は直接書き込み
        if len(data) <= self.buffer_size:
            return self._direct_write(data)

        # 巨大なデータの場合は一時ファイル経由で処理
        if len(data) > large_data_threshold:
            return self._write_large_data(data)

        # 中間サイズのデータの場合はチャンク単位で書き込み
        total_written = 0
        for i in range(0, len(data), self.buffer_size):
            chunk = data[i:i + self.buffer_size]
            written = self._direct_write(chunk)
            total_written += written

        return total_written

    def _direct_write(self, data: bytes) -> int:
        """
        ファイルに直接書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if not data:
            return 0

        fp = self.open()
        try:
            fp.write(data)
            fp.flush()
            self.bytes_written += len(data)
            return len(data)
        except Exception as e:
            print(f"警告: ファイル書き込み中にエラーが発生しました: {e}")
            raise  # 上位での処理のために例外を再送出

    def _write_large_data(self, data: bytes) -> int:
        """
        巨大なデータを一時ファイル経由で書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        # 一時ファイルを作成してデータを書き込む
        with tempfile.NamedTemporaryFile(delete=False, prefix="capsule_temp_") as temp_file:
            self.temp_files.append(temp_file.name)

            # チャンク単位でデータを書き込む
            total_size = len(data)
            bytes_written_temp = 0

            while bytes_written_temp < total_size:
                chunk_size = min(self.buffer_size, total_size - bytes_written_temp)
                chunk = data[bytes_written_temp:bytes_written_temp + chunk_size]
                temp_file.write(chunk)
                bytes_written_temp += chunk_size

            temp_file.flush()

        # 一時ファイルから出力ファイルにコピー
        total_written = 0
        with open(temp_file.name, 'rb') as f_in:
            while True:
                chunk = f_in.read(self.buffer_size)
                if not chunk:
                    break
                written = self._direct_write(chunk)
                total_written += written

        return total_written

    def cleanup(self):
        """一時ファイルを削除"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}")
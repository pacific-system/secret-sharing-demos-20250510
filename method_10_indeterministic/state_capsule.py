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

    def _initialize_mappings(self, data_size: int, block_size: int = 64):
        """
        インターリーブ・シャッフルマッピングを初期化

        Args:
            data_size: 処理するデータのサイズ
            block_size: ブロックサイズ
        """
        # 解析耐性レベルに応じてブロックサイズを調整
        if hasattr(self, '_block_size_modifier'):
            block_size = block_size * self._block_size_modifier

        # ブロックマッピングの初期化
        num_blocks = math.ceil(data_size / block_size)
        self._block_map = {}

        # 各ブロックの処理方法を決定
        for i in range(num_blocks):
            # ブロック処理方式の決定シード
            block_seed = hashlib.sha256(self._capsule_seed + f"block_{i}".encode()).digest()

            # 解析耐性レベルに応じてパターン数を増やす
            pattern_types = 3 + (self.resistance_level - 1)  # 基本3種類 + 耐性レベルに応じて増加
            if pattern_types > 10:
                pattern_types = 10  # 上限は10種類

            # ブロック処理タイプ [0:(pattern_types-1)]
            block_type = block_seed[0] % pattern_types

            # 基本3パターンに収める（拡張パターンは内部的に基本パターンにマッピング）
            mapped_type = block_type % 3

            # インターリーブの粒度（バイト単位or半分単位など）
            # 解析耐性が高いほど、より複雑なインターリーブパターンを使用
            max_granularity = 8 + (self.resistance_level * 2)
            interleave_granularity = max(1, block_seed[1] % max_granularity)

            # 拡張情報を追加（解析をさらに困難にする）
            extra_info = {}
            if self.resistance_level >= AnalysisResistanceLevel.HIGH:
                extra_info["subtype"] = block_seed[2] % 4
                extra_info["complexity"] = (block_seed[3] % 100) / 100.0
                extra_info["iteration"] = 1 + (block_seed[4] % 3)

            self._block_map[i] = {
                "type": mapped_type,
                "original_type": block_type,  # デバッグ用に元の値も保持
                "granularity": interleave_granularity,
                "extra": extra_info
            }

        # シャッフルマッピングの初期化
        total_size = data_size * 2  # 正規＋非正規
        self._shuffle_map = {}
        available_positions = list(range(total_size))

        # シャッフル回数を耐性レベルに応じて調整
        shuffle_iterations = 1
        if hasattr(self, '_shuffle_complexity'):
            shuffle_iterations = self._shuffle_complexity

        # 複数回のシャッフルでさらに攪拌
        for iteration in range(shuffle_iterations):
            # シャッフルシードを更新
            iteration_seed = hashlib.sha256(self._capsule_seed + iteration.to_bytes(4, 'big')).digest()

            # シャッフルマップの生成
            temp_map = {}
            available_temp = available_positions.copy()

            for i in range(total_size):
                # 決定論的なシャッフル（鍵に依存）
                shuffle_seed = hashlib.sha256(iteration_seed + f"shuffle_{i}".encode()).digest()
                index = int.from_bytes(shuffle_seed[:4], byteorder='big') % len(available_temp)
                position = available_temp.pop(index)
                temp_map[i] = position

            # 最初の反復の場合は直接設定、それ以降は追加シャッフル
            if iteration == 0:
                self._shuffle_map = temp_map
            else:
                # 前回のマップにさらにシャッフルを適用
                new_map = {}
                for src, mid in self._shuffle_map.items():
                    if mid in temp_map:
                        dst = temp_map[mid]
                        new_map[src] = dst
                    else:
                        new_map[src] = mid
                self._shuffle_map = new_map

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

        カプセルに署名を埋め込む前に解析困難化処理を行います。

        Args:
            signature: 署名データ

        Returns:
            前処理済み署名データ
        """
        # 署名長の確保
        if len(signature) > 256:
            signature = signature[:256]
        elif len(signature) < 256:
            padding = os.urandom(256 - len(signature))
            signature = signature + padding

        # 署名攪拌（解析対策）
        signature_key = hmac.new(self._capsule_seed, b"signature", hashlib.sha256).digest()
        processed = bytearray(len(signature))

        for i in range(len(signature)):
            key_byte = signature_key[i % len(signature_key)]
            src_byte = signature[i]
            # 単純な攪拌（復元可能な処理）
            processed[i] = (src_byte + key_byte) % 256

        # データ冗長性による解析対策（低レベルな攻撃への対策）
        if self.resistance_level >= AnalysisResistanceLevel.MEDIUM:
            checksum = hashlib.sha256(processed).digest()[:16]
            processed.extend(checksum)

        return bytes(processed)

    def _revert_signature(self, processed: bytes) -> bytes:
        """
        署名データの復元処理

        Args:
            processed: 前処理済み署名データ

        Returns:
            元の署名データ
        """
        # チェックサムの検証
        data_len = len(processed)
        if self.resistance_level >= AnalysisResistanceLevel.MEDIUM:
            data_len = len(processed) - 16
            data = processed[:data_len]
            checksum = processed[data_len:]
            expected = hashlib.sha256(data).digest()[:16]
            if checksum != expected:
                # チェックサム検証失敗時はダミー署名を返す
                return os.urandom(data_len)
        else:
            data = processed

        # 署名の復元
        signature_key = hmac.new(self._capsule_seed, b"signature", hashlib.sha256).digest()
        original = bytearray(data_len)

        for i in range(data_len):
            key_byte = signature_key[i % len(signature_key)]
            proc_byte = data[i]
            # 攪拌の逆処理
            original[i] = (proc_byte - key_byte) % 256

        return bytes(original)

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
        # 大規模データの判定
        large_data = len(true_data) > MAX_TEMP_FILE_SIZE or len(false_data) > MAX_TEMP_FILE_SIZE
        if large_data:
            return self._create_large_capsule(true_data, false_data, true_signature, false_signature)

        # 通常サイズのデータ処理
        return self._create_normal_capsule(true_data, false_data, true_signature, false_signature)

    def _create_normal_capsule(
        self,
        true_data: bytes,
        false_data: bytes,
        true_signature: bytes,
        false_signature: bytes
    ) -> bytes:
        """
        通常サイズのデータをカプセル化

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

    def _create_large_capsule(
        self,
        true_data: bytes,
        false_data: bytes,
        true_signature: bytes,
        false_signature: bytes
    ) -> bytes:
        """
        大規模データのカプセル化処理

        メモリ効率の良い実装で大容量ファイルを処理します。

        Args:
            true_data: 正規パスの暗号化データ
            false_data: 非正規パスの暗号化データ
            true_signature: 正規パスの署名
            false_signature: 非正規パスの署名

        Returns:
            カプセル化されたデータ
        """
        # 一時ファイルを使用
        temp_files = []

        try:
            # 入力データを一時ファイルに保存
            with tempfile.NamedTemporaryFile(delete=False, prefix="true_data_") as temp_true:
                temp_files.append(temp_true.name)
                temp_true.write(true_data)

            with tempfile.NamedTemporaryFile(delete=False, prefix="false_data_") as temp_false:
                temp_files.append(temp_false.name)
                temp_false.write(false_data)

            # 出力用一時ファイル
            temp_output = tempfile.NamedTemporaryFile(delete=False, prefix="capsule_output_")
            temp_files.append(temp_output.name)
            temp_output.close()

            # ブロックサイズの決定
            block_size = 64

            # マッピングの初期化
            # データサイズを計算
            true_size = len(true_data)
            false_size = len(false_data)
            max_size = max(true_size, false_size)
            self._initialize_mappings(max_size, block_size)

            # 署名データの前処理
            true_sig_processed = self._pre_process_signature(true_signature)
            false_sig_processed = self._pre_process_signature(false_signature)

            # 出力ファイルに署名を書き込む
            with open(temp_output.name, 'wb') as f_out:
                f_out.write(true_sig_processed)
                f_out.write(false_sig_processed)

            # ブロック単位で処理
            max_blocks = math.ceil(max_size / block_size)

            with open(temp_true.name, 'rb') as f_true, \
                 open(temp_false.name, 'rb') as f_false, \
                 open(temp_output.name, 'ab') as f_out:

                for i in range(max_blocks):
                    # 各ファイルからブロックを読み込む
                    true_block = f_true.read(block_size)
                    false_block = f_false.read(block_size)

                    # パディングを適用
                    if len(true_block) < block_size:
                        seed = self._capsule_seed + f"true_padding_{i}".encode()
                        dummy = hashlib.sha256(seed).digest()[:block_size - len(true_block)]
                        true_block = true_block + dummy

                    if len(false_block) < block_size:
                        seed = self._capsule_seed + f"false_padding_{i}".encode()
                        dummy = hashlib.sha256(seed).digest()[:block_size - len(false_block)]
                        false_block = false_block + dummy

                    # ブロックを処理
                    block_info = self._block_map.get(i, {"type": 0, "granularity": 1})
                    mixed_block = self._create_block_interleave(true_block, false_block, block_info)
                    f_out.write(mixed_block)

            # メモリ効率の良いシャッフル処理
            self._apply_shuffle_to_file(temp_output.name)

            # 最終結果を読み込む
            with open(temp_output.name, 'rb') as f:
                result = f.read()

            return result

        finally:
            # 一時ファイルの削除
            for file in temp_files:
                try:
                    if os.path.exists(file):
                        os.unlink(file)
                except Exception as e:
                    print(f"警告: 一時ファイル '{file}' の削除に失敗しました: {e}")

    def _apply_shuffle_to_file(self, file_path: str):
        """
        ファイルに対してシャッフル処理を適用する

        メモリ効率を考慮したファイルベースのシャッフル処理を行います。

        Args:
            file_path: シャッフルするファイルのパス
        """
        # 一時ファイルを作成
        temp_shuffled = tempfile.NamedTemporaryFile(delete=False, prefix="shuffled_")
        temp_shuffled.close()

        try:
            # ファイルサイズを取得
            file_size = os.path.getsize(file_path)

            # 空のシャッフル先ファイルを作成
            with open(temp_shuffled.name, 'wb') as f:
                f.write(b'\x00' * file_size)

            # 元ファイルを開く
            with open(file_path, 'rb') as source, open(temp_shuffled.name, 'r+b') as target:
                # バッファ単位でシャッフル
                buffer_size = min(BUFFER_SIZE, file_size // 10)  # 最大でもファイルの1/10のサイズ
                if buffer_size < 1024:
                    buffer_size = 1024  # 最小サイズ保証

                # 読み込み位置の管理
                source_pos = 0

                while source_pos < file_size:
                    # バッファサイズを調整（ファイル末尾では小さくなる）
                    current_buffer = min(buffer_size, file_size - source_pos)

                    # バッファを読み込み
                    source.seek(source_pos)
                    buffer = source.read(current_buffer)

                    # バッファ内の各バイトをシャッフル
                    for offset in range(len(buffer)):
                        src_pos = source_pos + offset
                        if src_pos in self._shuffle_map:
                            dst_pos = self._shuffle_map[src_pos]
                            if dst_pos < file_size:
                                # シャッフル先の位置に書き込み
                                target.seek(dst_pos)
                                target.write(bytes([buffer[offset]]))

                    # 次のバッファへ
                    source_pos += current_buffer

            # 結果を元のファイルにコピー
            with open(temp_shuffled.name, 'rb') as source, open(file_path, 'wb') as target:
                # チャンク単位でコピー
                while True:
                    chunk = source.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    target.write(chunk)

        finally:
            # 一時ファイルを削除
            try:
                if os.path.exists(temp_shuffled.name):
                    os.unlink(temp_shuffled.name)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_shuffled.name}' の削除に失敗しました: {e}")

    def _extract_block_true(self, mixed_block: bytes, block_info: Dict) -> bytes:
        """
        混合ブロックから正規データを抽出

        Args:
            mixed_block: 混合されたブロック
            block_info: ブロック処理情報

        Returns:
            抽出された正規データ
        """
        # ブロックタイプ抽出
        block_type = block_info.get("type", 0)
        granularity = block_info.get("granularity", 1)
        extra = block_info.get("extra", {})

        # ブロックタイプに基づいて抽出処理
        if block_type == 0:
            # パターン0: 交互配置（インターリーブ）
            return bytes([mixed_block[i] for i in range(0, len(mixed_block), 2)])

        elif block_type == 1:
            # パターン1: 順次配置（true全体 + false全体）
            return mixed_block[:len(mixed_block)//2]

        elif block_type == 2:
            # パターン2: 粒度付きのインターリーブ
            result = bytearray()
            i = 0

            while i < len(mixed_block):
                # 正規データチャンク
                chunk_size = min(granularity, len(mixed_block) - i)
                result.extend(mixed_block[i:i+chunk_size])
                i += chunk_size

                # 非正規データチャンクはスキップ
                i += min(granularity, max(0, len(mixed_block) - i))

            return bytes(result)

        # 未知のタイプの場合はデフォルトの抽出方法
        return bytes([mixed_block[i] for i in range(0, len(mixed_block), 2)])

    def _extract_block_false(self, mixed_block: bytes, block_info: Dict) -> bytes:
        """
        混合ブロックから非正規データを抽出

        Args:
            mixed_block: 混合されたブロック
            block_info: ブロック処理情報

        Returns:
            抽出された非正規データ
        """
        # ブロックタイプ抽出
        block_type = block_info.get("type", 0)
        granularity = block_info.get("granularity", 1)
        extra = block_info.get("extra", {})

        # ブロックタイプに基づいて抽出処理
        if block_type == 0:
            # パターン0: 交互配置（インターリーブ）
            return bytes([mixed_block[i] for i in range(1, len(mixed_block), 2)])

        elif block_type == 1:
            # パターン1: 順次配置（true全体 + false全体）
            midpoint = len(mixed_block)//2
            return mixed_block[midpoint:]

        elif block_type == 2:
            # パターン2: 粒度付きのインターリーブ
            result = bytearray()
            i = 0

            while i < len(mixed_block):
                # 正規データチャンクはスキップ
                i += min(granularity, max(0, len(mixed_block) - i))

                # 非正規データチャンク
                if i < len(mixed_block):
                    chunk_size = min(granularity, len(mixed_block) - i)
                    result.extend(mixed_block[i:i+chunk_size])
                    i += chunk_size

            return bytes(result)

        # 未知のタイプの場合はデフォルトの抽出方法
        return bytes([mixed_block[i] for i in range(1, len(mixed_block), 2)])


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
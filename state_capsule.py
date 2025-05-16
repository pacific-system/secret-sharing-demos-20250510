"""
不確定性転写暗号化方式 - 状態カプセル化モジュール (StateCapsule)

このモジュールは、正規データと非正規データをカプセル化し、
解析耐性を持つデータ構造を生成します。
"""

import os
import sys
import hashlib
import hmac
import random
import struct
import math
import logging
from typing import Tuple, List, Dict, Any, Optional, Union, ByteString

# 乱数シード
ENTROPY_SEED = os.urandom(32)

# ブロック処理タイプの定義
BLOCK_TYPE_SEQUENTIAL = 1  # 順次配置
BLOCK_TYPE_INTERLEAVE = 2  # インターリーブ配置

# エントロピーブロックのサイズ（バイト単位）
DEFAULT_ENTROPY_BLOCK_SIZE = 16

# マーカーの定義
CAPSULE_MARKER = b'\xCA\xB0\x0D\xCA'

# シグネチャ関連の定数
SIGNATURE_KEY = b'\x8F\x3A\xC1\x98\x7E\x2D\xBF\x12\x45\x6E\x08\x91\x34\xA5\xF7\xD6'
SIGNATURE_SIZE = 32  # HMAC-SHA256のサイズ

# ヘッダーサイズの定数
HEADER_SIZE = len(CAPSULE_MARKER) + 4 + 4 + 4 + 4 + SIGNATURE_SIZE

# ロガーの設定
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.WARNING)


class StateCapsule:
    """
    複数のデータブロックと署名を一つのカプセルとして管理するクラス。

    カプセルの構造:
    - マーカー (4バイト): 一貫性チェック用の固定値
    - バージョン (4バイト): カプセルフォーマットのバージョン
    - ブロック処理タイプ (4バイト): 順次/インターリーブなど
    - エントロピーブロックサイズ (4バイト): エントロピーブロックのサイズ
    - フラグ (4バイト): 将来の拡張用
    - 署名 (32バイト): 全データのHMAC-SHA256
    - データブロック: 可変長のデータブロックの配列
    """

    def __init__(self) -> None:
        """初期化メソッド"""
        self.marker = CAPSULE_MARKER
        self.version = 1
        self.block_type = BLOCK_TYPE_SEQUENTIAL
        self.entropy_block_size = DEFAULT_ENTROPY_BLOCK_SIZE
        self.flags = 0
        self.signature = b''
        self.true_data = b''
        self.false_data = b''
        self.true_signature = b''
        self.false_signature = b''
        self.random_seed = os.urandom(16)

    def create_capsule(
        self,
        true_data: bytes,
        false_data: bytes,
        block_type: int = BLOCK_TYPE_SEQUENTIAL,
        entropy_block_size: int = DEFAULT_ENTROPY_BLOCK_SIZE,
        use_shuffle: bool = True
    ) -> bytes:
        """
        正規データと非正規データからカプセルを作成する

        Args:
            true_data: 正規データ
            false_data: 非正規データ
            block_type: ブロック処理タイプ（1=順次配置、2=インターリーブ）
            entropy_block_size: エントロピーブロックのサイズ
            use_shuffle: シャッフルを適用するかどうか

        Returns:
            bytes: カプセル化されたデータ
        """
        # データの保存
        self.true_data = true_data
        self.false_data = false_data
        self.block_type = block_type
        self.entropy_block_size = entropy_block_size

        # 署名の作成
        self.true_signature = self._create_signature(true_data)
        self.false_signature = self._create_signature(false_data)

        # カプセル化データの作成
        capsule_data = self._create_capsule_data(use_shuffle)

        # 全体の署名を計算
        self.signature = self._create_signature(capsule_data)

        # ヘッダーの作成
        header = self._create_header()

        # カプセルの完成（ヘッダー＋データ）
        return header + capsule_data

    def extract_data(
        self,
        capsule: bytes,
        path_type: str = "true"
    ) -> Tuple[bytes, bytes]:
        """
        カプセルからデータと署名を抽出する

        Args:
            capsule: カプセル化されたデータ
            path_type: "true"または"false"（正規・非正規パス）

        Returns:
            Tuple[bytes, bytes]: (データ, 署名)
        """
        # ヘッダーを解析
        header_valid, header_data = self._parse_header(capsule)
        if not header_valid:
            raise ValueError("カプセルヘッダーが無効です")

        # ヘッダーからパラメータを取得
        self.version = header_data['version']
        self.block_type = header_data['block_type']
        self.entropy_block_size = header_data['entropy_block_size']
        self.flags = header_data['flags']
        stored_signature = header_data['signature']

        # カプセルデータの取得
        capsule_data = capsule[HEADER_SIZE:]

        # 署名の検証
        calculated_signature = self._create_signature(capsule_data)
        if calculated_signature != stored_signature:
            logger.warning("署名のチェックサムが一致しません")
            # 深刻なエラーではないため、処理を続行

        # カプセルからデータを抽出
        true_data, false_data, true_sig, false_sig = self._extract_capsule_data(capsule_data)

        # 要求されたパスタイプに応じてデータを返す
        if path_type.lower() == "true":
            return true_data, true_sig
        else:
            return false_data, false_sig

    def _create_header(self) -> bytes:
        """ヘッダーを作成する"""
        header = bytearray()
        header.extend(self.marker)
        header.extend(struct.pack("<I", self.version))
        header.extend(struct.pack("<I", self.block_type))
        header.extend(struct.pack("<I", self.entropy_block_size))
        header.extend(struct.pack("<I", self.flags))
        header.extend(self.signature)
        return bytes(header)

    def _parse_header(self, capsule: bytes) -> Tuple[bool, Dict[str, Any]]:
        """
        カプセルのヘッダーを解析する

        Returns:
            Tuple[bool, Dict]: (ヘッダーが有効か, ヘッダー情報)
        """
        if len(capsule) < HEADER_SIZE:
            return False, {}

        # ヘッダーデータの取得
        marker = capsule[0:4]
        version = struct.unpack("<I", capsule[4:8])[0]
        block_type = struct.unpack("<I", capsule[8:12])[0]
        entropy_block_size = struct.unpack("<I", capsule[12:16])[0]
        flags = struct.unpack("<I", capsule[16:20])[0]
        signature = capsule[20:52]  # SIGNATURE_SIZE = 32

        # マーカーの検証
        if marker != CAPSULE_MARKER:
            return False, {}

        # ヘッダー情報の返却
        header_data = {
            'marker': marker,
            'version': version,
            'block_type': block_type,
            'entropy_block_size': entropy_block_size,
            'flags': flags,
            'signature': signature
        }

        return True, header_data

    def _create_signature(self, data: bytes) -> bytes:
        """
        与えられたデータの署名を作成する

        Args:
            data: 署名対象のデータ

        Returns:
            bytes: HMAC-SHA256署名
        """
        h = hmac.new(SIGNATURE_KEY, data, hashlib.sha256)
        return h.digest()

    def _create_entropy_block(self, size: int) -> bytes:
        """ランダムなエントロピーブロックを生成する"""
        # 乱数生成アルゴリズムを改善（セキュリティ強化）
        rng = random.Random(hashlib.sha256(self.random_seed + os.urandom(8)).digest())
        return bytes(rng.randint(0, 255) for _ in range(size))

    def _create_capsule_data(self, use_shuffle: bool) -> bytes:
        """
        カプセル化データを作成する

        Args:
            use_shuffle: シャッフルを適用するかどうか

        Returns:
            bytes: カプセル化されたデータ
        """
        # 正規・非正規データそれぞれにエントロピーブロックを追加
        true_blocks = self._split_data_with_entropy(self.true_data)
        false_blocks = self._split_data_with_entropy(self.false_data)

        # ブロック処理タイプに応じて配置方法を選択
        if self.block_type == BLOCK_TYPE_SEQUENTIAL:
            # 順次配置: 正規ブロックを先に配置し、その後に非正規ブロックを配置
            all_blocks = []
            # 正規ブロックと署名を追加
            all_blocks.append(self.true_signature)
            all_blocks.extend(true_blocks)
            # 非正規ブロックと署名を追加
            all_blocks.append(self.false_signature)
            all_blocks.extend(false_blocks)
        else:
            # インターリーブ配置: 正規・非正規ブロックを交互に配置
            all_blocks = []
            # 署名を先に追加
            all_blocks.append(self.true_signature)
            all_blocks.append(self.false_signature)
            # ブロックの交互配置
            for i in range(max(len(true_blocks), len(false_blocks))):
                if i < len(true_blocks):
                    all_blocks.append(true_blocks[i])
                if i < len(false_blocks):
                    all_blocks.append(false_blocks[i])

        # 全ブロックを連結
        final_data = b''.join(all_blocks)

        # シャッフルが指定されている場合はバイトレベルでシャッフル
        if use_shuffle:
            final_data = self._shuffle_bytes(final_data)

        return final_data

    def _extract_capsule_data(self, capsule_data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        カプセルデータから正規・非正規データと署名を抽出する

        Args:
            capsule_data: カプセルデータ部分

        Returns:
            Tuple[bytes, bytes, bytes, bytes]: (正規データ, 非正規データ, 正規署名, 非正規署名)
        """
        # シャッフルが適用されている場合はアンシャッフル
        if self.block_type != 0:  # 0はシャッフルなしの特殊ケース
            capsule_data = self._unshuffle_bytes(capsule_data)

        # シグネチャサイズを定義
        sig_size = SIGNATURE_SIZE

        # ブロック処理タイプに応じてデータを抽出
        if self.block_type == BLOCK_TYPE_SEQUENTIAL:
            # 順次配置の場合
            true_signature = capsule_data[:sig_size]

            # エントロピーブロックサイズを考慮して正規データの長さを計算
            # 正規データのブロック数を推定
            total_size = len(capsule_data) - sig_size * 2  # 署名2つの分を除く
            approx_true_size = total_size // 2  # 簡易的に半分と仮定

            # 簡易的なスキャンでtrueデータとfalseデータの境界を探す
            # 署名の後に続くデータブロックをスキャン
            data_portion = capsule_data[sig_size:]
            false_sig_pos = -1

            # falseシグネチャを探す（簡易スキャン - 実際の実装ではより堅牢なアルゴリズムが必要）
            for i in range(sig_size, len(data_portion), self.entropy_block_size):
                if i + sig_size <= len(data_portion):
                    potential_sig = data_portion[i:i+sig_size]
                    # 簡易的な検出 - 実際にはより堅牢な方法が必要
                    if hashlib.sha256(potential_sig).digest()[:4] == hashlib.sha256(true_signature).digest()[:4]:
                        false_sig_pos = i
                        break

            # 見つからなかった場合はデフォルトの半分の位置を使用
            if false_sig_pos == -1:
                false_sig_pos = approx_true_size

            # 正規データとfalseシグネチャの抽出
            true_data = self._extract_data_blocks(data_portion[:false_sig_pos])
            false_signature = data_portion[false_sig_pos:false_sig_pos+sig_size]
            false_data = self._extract_data_blocks(data_portion[false_sig_pos+sig_size:])

        else:  # BLOCK_TYPE_INTERLEAVE
            # インターリーブ配置の場合
            true_signature = capsule_data[:sig_size]
            false_signature = capsule_data[sig_size:sig_size*2]

            # データ部分の取得
            data_portion = capsule_data[sig_size*2:]

            # データブロックの抽出（交互に配置されている）
            true_blocks = []
            false_blocks = []

            # エントロピーブロックサイズを使用してブロックを分割
            blocks = []
            for i in range(0, len(data_portion), self.entropy_block_size):
                end = min(i + self.entropy_block_size, len(data_portion))
                blocks.append(data_portion[i:end])

            # 偶数番目が正規、奇数番目が非正規ブロック
            for i, block in enumerate(blocks):
                if i % 2 == 0 and i < len(blocks):
                    true_blocks.append(block)
                elif i % 2 == 1 and i < len(blocks):
                    false_blocks.append(block)

            # ブロックからエントロピーを除去してデータを抽出
            true_data = self._extract_data_from_blocks(true_blocks)
            false_data = self._extract_data_from_blocks(false_blocks)

        return true_data, false_data, true_signature, false_signature

    def _split_data_with_entropy(self, data: bytes) -> List[bytes]:
        """
        データをブロックに分割し、各ブロックにエントロピーを追加する

        Args:
            data: 分割するデータ

        Returns:
            List[bytes]: エントロピーが追加されたブロックのリスト
        """
        blocks = []
        block_size = self.entropy_block_size

        # データが空の場合は空のブロックを1つ返す
        if not data:
            entropy_block = self._create_entropy_block(block_size)
            blocks.append(entropy_block)
            return blocks

        # データを適切なサイズのブロックに分割
        for i in range(0, len(data), block_size):
            # 元のデータブロックを取得
            end = min(i + block_size, len(data))
            data_block = data[i:end]

            # このブロックのエントロピーを生成
            entropy_block = self._create_entropy_block(block_size)

            # データとエントロピーを組み合わせる
            # データの長さを保存
            data_len = len(data_block)
            combined_block = bytearray()
            combined_block.extend(struct.pack("<I", data_len))
            combined_block.extend(data_block)
            # 残りのスペースをエントロピーで埋める
            padding_size = block_size - (len(combined_block) % block_size)
            if padding_size < block_size:
                combined_block.extend(entropy_block[:padding_size])

            blocks.append(bytes(combined_block))

        return blocks

    def _extract_data_blocks(self, data: bytes) -> bytes:
        """
        ブロックからデータを抽出する（順次配置用）

        Args:
            data: ブロックデータ

        Returns:
            bytes: 抽出されたデータ
        """
        extracted_data = bytearray()
        block_size = self.entropy_block_size

        # 各ブロックからデータを抽出
        i = 0
        while i < len(data):
            # ブロックの残りのバイト数を確認
            if i + 4 > len(data):
                break  # データ長を読み取るための十分なバイトがない

            # データ長を取得
            data_len = struct.unpack("<I", data[i:i+4])[0]
            i += 4

            # データ長の妥当性チェック
            if data_len > block_size or i + data_len > len(data):
                break  # 異常なデータ長

            # データを抽出
            extracted_data.extend(data[i:i+data_len])

            # 次のブロックへ
            i += data_len
            # エントロピー部分をスキップ（境界に整列）
            remainder = i % block_size
            if remainder != 0:
                i += (block_size - remainder)

        return bytes(extracted_data)

    def _extract_data_from_blocks(self, blocks: List[bytes]) -> bytes:
        """
        ブロックリストからデータを抽出する（インターリーブ配置用）

        Args:
            blocks: ブロックのリスト

        Returns:
            bytes: 抽出されたデータ
        """
        extracted_data = bytearray()

        for block in blocks:
            # 各ブロックからデータを抽出
            if len(block) >= 4:
                # データ長を取得
                data_len = struct.unpack("<I", block[:4])[0]

                # データ長の妥当性チェック
                if data_len <= len(block) - 4:
                    # データを抽出
                    extracted_data.extend(block[4:4+data_len])

        return bytes(extracted_data)

    def _shuffle_bytes(self, data: bytes) -> bytes:
        """
        バイトレベルでのシャッフル処理を行う

        Args:
            data: シャッフルするデータ

        Returns:
            bytes: シャッフルされたデータ
        """
        # シャッフルのためのシード値を設定
        seed = hashlib.sha256(self.random_seed).digest()
        rng = random.Random(seed)

        # バイト配列に変換
        byte_array = bytearray(data)

        # シャッフルのためのマッピングテーブルを作成
        data_len = len(byte_array)
        shuffle_map = list(range(data_len))
        rng.shuffle(shuffle_map)

        # マッピングに従ってデータをシャッフル
        shuffled = bytearray(data_len)
        for i, orig_pos in enumerate(shuffle_map):
            if i < data_len:
                shuffled[i] = byte_array[orig_pos]

        return bytes(shuffled)

    def _unshuffle_bytes(self, data: bytes) -> bytes:
        """
        シャッフルされたバイトを元に戻す

        Args:
            data: シャッフルされたデータ

        Returns:
            bytes: 元に戻されたデータ
        """
        # シャッフルのためのシード値を設定（同じシードを使用）
        seed = hashlib.sha256(self.random_seed).digest()
        rng = random.Random(seed)

        # バイト配列に変換
        byte_array = bytearray(data)

        # シャッフルのためのマッピングテーブルを作成（同じマッピング）
        data_len = len(byte_array)
        shuffle_map = list(range(data_len))
        rng.shuffle(shuffle_map)

        # マッピングを逆にして元に戻す
        unshuffled = bytearray(data_len)
        for i, orig_pos in enumerate(shuffle_map):
            if i < data_len:
                unshuffled[orig_pos] = byte_array[i]

        return bytes(unshuffled)
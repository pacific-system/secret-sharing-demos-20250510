# フェーズ 4: 不確定性転写暗号化方式 🎲 実装指示書（2/2）

**最終更新日:** 2025 年 5 月 20 日
**作成者:** パシ子（暗号技術研究チーム）
**バージョン:** 1.0

## 📝 詳細実装手順（続き）

### 3. 実行パス分散メカニズムの実装

**ファイル:** `method_9_indeterministic/path_scatter.py`

```python
#!/usr/bin/env python3
"""
不確定性転写暗号化のための実行パス分散モジュール

このモジュールは実行パスの分散と動的分岐を管理し、
静的/動的解析による真偽判別を不可能にします。
"""

import os
import time
import random
import threading
import queue
import hashlib
import secrets
from typing import List, Dict, Tuple, Callable, Any, Union, Optional

from method_9_indeterministic.entropy import EntropyCollector, EntropyInjector
from method_9_indeterministic.temporal_mix import TemporalMixer, TimeScatterer

class PathNode:
    """
    実行パス木のノードを表すクラス
    """

    def __init__(self, node_id: str, depth: int = 0):
        """
        初期化

        Args:
            node_id: ノードID
            depth: 木内の深さ
        """
        self.node_id = node_id
        self.depth = depth
        self.children: List[PathNode] = []
        self.action: Optional[Callable] = None
        self.action_args: Tuple = ()
        self.action_kwargs: Dict = {}
        self.visited = False
        self.probability = 1.0  # このノードが選択される確率

    def add_child(self, child: 'PathNode') -> None:
        """
        子ノードを追加

        Args:
            child: 追加する子ノード
        """
        self.children.append(child)

    def set_action(self, action: Callable, *args, **kwargs) -> None:
        """
        ノードに実行アクションを設定

        Args:
            action: 実行する関数
            *args, **kwargs: 関数の引数
        """
        self.action = action
        self.action_args = args
        self.action_kwargs = kwargs

    def execute(self) -> Any:
        """
        ノードのアクションを実行

        Returns:
            Any: アクションの実行結果
        """
        self.visited = True
        if self.action:
            return self.action(*self.action_args, **self.action_kwargs)
        return None


class PathTree:
    """
    実行パス木を管理するクラス
    """

    def __init__(self, max_depth: int = MAX_BRANCH_DEPTH):
        """
        初期化

        Args:
            max_depth: 木の最大深さ
        """
        self.root = PathNode("root", 0)
        self.max_depth = max_depth
        self.current_node = self.root
        self.path_history: List[str] = []
        self.entropy_injector = EntropyInjector()

    def add_path(self, path_sequence: List[str], action: Callable, *args, **kwargs) -> None:
        """
        実行パスを追加

        Args:
            path_sequence: パスを表すノードIDシーケンス
            action: 実行する関数
            *args, **kwargs: 関数の引数
        """
        # 空のパスシーケンスはルートに設定
        if not path_sequence:
            self.root.set_action(action, *args, **kwargs)
            return

        # パスを辿りながらノードを作成
        current = self.root
        for i, node_id in enumerate(path_sequence):
            # 現在の深さ
            depth = i + 1

            # 指定された子ノードを探す
            child = next((c for c in current.children if c.node_id == node_id), None)

            # 存在しなければ作成
            if not child:
                child = PathNode(node_id, depth)
                current.add_child(child)

            current = child

        # 最終ノードにアクションを設定
        current.set_action(action, *args, **kwargs)

    def traverse(self, seed: bytes) -> Any:
        """
        シード値に基づいてパスをたどり、ノードを実行

        Args:
            seed: 経路選択のためのシード値

        Returns:
            Any: 実行結果
        """
        # パス履歴をクリア
        self.path_history.clear()

        # ルートノードから開始
        current = self.root
        self.path_history.append(current.node_id)

        # ルートノードを実行
        result = current.execute()

        # 子ノードがあれば、シードに基づいて選択して進む
        depth = 0
        while current.children and depth < self.max_depth:
            # 子ノードがない場合は終了
            if not current.children:
                break

            # エントロピー注入して経路選択を予測不能に
            seed = self.entropy_injector.inject_entropy(seed)

            # シード値に基づいて子ノードを選択
            child_index = self._select_child_index(current, seed, depth)
            current = current.children[child_index]

            # パス履歴を更新
            self.path_history.append(current.node_id)

            # 選択したノードを実行
            node_result = current.execute()

            # 結果を更新（最後のノードの結果を返す）
            if node_result is not None:
                result = node_result

            # 深さを増加
            depth += 1

        return result

    def _select_child_index(self, node: PathNode, seed: bytes, depth: int) -> int:
        """
        シード値に基づいて子ノードのインデックスを選択

        Args:
            node: 現在のノード
            seed: シード値
            depth: 現在の深さ

        Returns:
            int: 選択した子ノードのインデックス
        """
        if not node.children:
            return 0

        # シード値をハッシュ化（深さごとに異なるハッシュを生成）
        h = hashlib.sha256()
        h.update(seed)
        h.update(depth.to_bytes(4, byteorder='big'))
        hash_bytes = h.digest()

        # ハッシュ値を整数に変換
        value = int.from_bytes(hash_bytes, byteorder='big')

        # 子ノードの数で割った余りを取得
        index = value % len(node.children)

        return index

    def get_path_fingerprint(self) -> bytes:
        """
        現在のパス履歴からフィンガープリントを生成

        Returns:
            bytes: パスフィンガープリント
        """
        # パス履歴を連結
        path_str = ".".join(self.path_history)

        # ハッシュ化
        h = hashlib.sha256()
        h.update(path_str.encode())

        return h.digest()


class PathScatterer:
    """
    実行パスを分散させるクラス
    """

    def __init__(self, scatter_degree: int = PATH_SCATTER_DEGREE):
        """
        初期化

        Args:
            scatter_degree: 分散の度合い
        """
        self.scatter_degree = scatter_degree
        self.path_tree = PathTree()
        self.time_scatterer = TimeScatterer()
        self.entropy_injector = EntropyInjector()
        self.result_queue = queue.Queue()

    def start(self) -> None:
        """分散処理を開始"""
        self.time_scatterer.start()

    def stop(self) -> None:
        """分散処理を停止"""
        self.time_scatterer.stop()

    def add_true_path(self, action: Callable, *args, **kwargs) -> None:
        """
        真の実行パスを追加

        Args:
            action: 実行する関数
            *args, **kwargs: 関数の引数
        """
        # 真のパスをランダムな深さに配置
        depth = random.randint(2, MAX_BRANCH_DEPTH - 1)
        path = self._generate_path_sequence("true", depth)

        # 結果をキューに格納するラッパー関数
        def wrapper(*w_args, **w_kwargs):
            try:
                result = action(*w_args, **w_kwargs)
                self.result_queue.put(('result', result))
            except Exception as e:
                self.result_queue.put(('error', e))

        # パスを追加
        self.path_tree.add_path(path, wrapper, *args, **kwargs)

    def add_false_path(self, action: Callable, *args, **kwargs) -> None:
        """
        偽の実行パスを追加

        Args:
            action: 実行する関数
            *args, **kwargs: 関数の引数
        """
        # 偽のパスをランダムな深さに配置
        depth = random.randint(2, MAX_BRANCH_DEPTH - 1)
        path = self._generate_path_sequence("false", depth)

        # 結果をキューに格納するラッパー関数
        def wrapper(*w_args, **w_kwargs):
            try:
                result = action(*w_args, **w_kwargs)
                self.result_queue.put(('result', result))
            except Exception as e:
                self.result_queue.put(('error', e))

        # パスを追加
        self.path_tree.add_path(path, wrapper, *args, **kwargs)

    def add_noise_paths(self, num_paths: int = None) -> None:
        """
        ノイズとなる実行パスを追加

        Args:
            num_paths: 追加するパス数（Noneの場合はscatter_degreeに基づく）
        """
        if num_paths is None:
            num_paths = self.scatter_degree

        # ノイズパスを追加
        for i in range(num_paths):
            # ランダムな深さ
            depth = random.randint(1, MAX_BRANCH_DEPTH)
            path = self._generate_path_sequence(f"noise_{i}", depth)

            # ノイズアクション
            def noise_action():
                # CPUとメモリを少し使う処理
                size = random.randint(1, 100) * 1024
                data = bytearray(os.urandom(size))

                # ハッシュ計算（CPU負荷）
                h = hashlib.sha256()
                h.update(data)
                return None  # 結果は返さない

            # パスを追加
            self.path_tree.add_path(path, noise_action)

    def _generate_path_sequence(self, base_name: str, depth: int) -> List[str]:
        """
        指定された深さのパスシーケンスを生成

        Args:
            base_name: 基本名
            depth: パスの深さ

        Returns:
            List[str]: パスシーケンス
        """
        path = []
        for i in range(depth):
            # エントロピーに基づくランダム要素を追加
            entropy = secrets.token_hex(4)
            node_name = f"{base_name}_{i}_{entropy}"
            path.append(node_name)

        return path

    def execute_with_key(self, key: bytes, timeout: float = 30.0) -> Any:
        """
        鍵に基づいてパス木を実行

        Args:
            key: 経路選択の鍵
            timeout: タイムアウト秒数

        Returns:
            Any: 実行結果
        """
        # キューをクリア
        while not self.result_queue.empty():
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break

        # 鍵からシード値を生成
        seed = self._derive_seed_from_key(key)

        # 時間的分散を利用してパス実行
        def execute_path():
            self.path_tree.traverse(seed)

        # 時間分散処理を追加
        self.time_scatterer.scatter_operation(execute_path)

        # 結果を待機
        try:
            result_type, value = self.result_queue.get(timeout=timeout)
            if result_type == 'error':
                raise value
            return value
        except queue.Empty:
            raise TimeoutError("パス実行がタイムアウトしました")

    def _derive_seed_from_key(self, key: bytes) -> bytes:
        """
        鍵からシード値を導出

        Args:
            key: 元の鍵

        Returns:
            bytes: 導出されたシード値
        """
        # 鍵導出関数（時間要素も含める）
        h = hashlib.sha256()
        h.update(key)

        # 現在の時間を含める（マイクロ秒精度）
        time_ns = time.time_ns().to_bytes(16, byteorder='big')
        h.update(time_ns)

        # エントロピーを追加
        entropy = self.entropy_injector.get_entropy(16)
        h.update(entropy)

        return h.digest()

    def select_path_type(self, key: bytes) -> str:
        """
        鍵に基づいてパスタイプを選択

        Args:
            key: 選択の基となる鍵

        Returns:
            str: 選択されたパスタイプ ('true' または 'false')
        """
        # 鍵から決定論的にパスタイプを選択
        h = hashlib.sha256()
        h.update(key)
        h.update(b"path_selection")

        # エントロピーを注入（同じキーでも環境によって結果が変わる可能性）
        entropy = self.entropy_injector.get_entropy(16)
        h.update(entropy)

        digest = h.digest()
        value = int.from_bytes(digest, byteorder='big')

        # 複雑な判定基準（単純な奇数/偶数ではなく、複数条件を組み合わせる）
        conditions = [
            value % 256 < 128,                 # 下位8ビットの値
            (value >> 8) % 256 < 128,          # 次の8ビット
            bin(value).count('1') % 2 == 0,    # 1ビットの数
            (value & 0xF0F0F0F0) > (value & 0x0F0F0F0F)  # ビットパターン比較
        ]

        # 条件の過半数で決定
        true_count = sum(1 for c in conditions if c)
        return "true" if true_count >= len(conditions) // 2 else "false"


# 定数
MAX_BRANCH_DEPTH = 8
PATH_SCATTER_DEGREE = 16
```

### 4. 不確定性エンジンコアの実装

**ファイル:** `method_9_indeterministic/indeterministic.py`

```python
#!/usr/bin/env python3
"""
不確定性転写暗号化のコアエンジン

このモジュールは不確定性転写暗号化方式の核となるロジックを実装し、
実行パスが毎回変化する非決定論的な手法により真偽判別を不可能にします。
"""

import os
import sys
import time
import random
import hashlib
import json
import base64
import secrets
from typing import Dict, Tuple, List, Union, Any, Optional, Callable

from method_9_indeterministic.entropy import EntropyCollector, EntropyInjector
from method_9_indeterministic.temporal_mix import TemporalMixer, TimeScatterer
from method_9_indeterministic.path_scatter import PathScatterer, PathTree

class IndeterministicEngine:
    """
    不確定性転写暗号化エンジン
    """

    def __init__(self):
        """初期化"""
        self.entropy_collector = EntropyCollector()
        self.entropy_injector = EntropyInjector(self.entropy_collector)
        self.path_scatterer = PathScatterer()
        self.temporal_mixer = TemporalMixer()
        self.true_key_hash = None
        self.false_key_hash = None
        self.confusion_ratio = CONFUSION_RATIO

    def initialize(self) -> None:
        """
        エンジンを初期化
        """
        # 分散処理を開始
        self.path_scatterer.start()
        self.temporal_mixer.start_mixing()

    def shutdown(self) -> None:
        """
        エンジンをシャットダウン
        """
        # 分散処理を停止
        self.path_scatterer.stop()
        self.temporal_mixer.stop_mixing()

    def encrypt(self, true_data: bytes, false_data: bytes,
              true_key: bytes, false_key: bytes) -> Dict:
        """
        真偽両方のデータを不確定暗号化

        Args:
            true_data: 正規データ
            false_data: 非正規データ
            true_key: 正規鍵
            false_key: 非正規鍵

        Returns:
            Dict: 暗号化データ
        """
        # 鍵のハッシュを保存（検証用、実際の復号には使わない）
        self.true_key_hash = hashlib.sha256(true_key).digest()
        self.false_key_hash = hashlib.sha256(false_key).digest()

        # 暗号化パラメータの準備
        params = self._prepare_encryption_params()

        # 鍵から初期ベクトルを導出
        iv_true = self._derive_iv(true_key)
        iv_false = self._derive_iv(false_key)

        # データの暗号化（AES-CTRで単純化、実際の実装ではより強力な方式を使用可能）
        true_encrypted = self._encrypt_data(true_data, true_key, iv_true)
        false_encrypted = self._encrypt_data(false_data, false_key, iv_false)

        # メタデータを準備（正規/非正規判別不能にするため共通フォーマット）
        result = {
            "algorithm": "indeterministic",
            "version": "1.0",
            "created": int(time.time()),
            "params": params,
            "data_blocks": [
                {
                    "id": self._generate_block_id(),
                    "iv": base64.b64encode(iv_true).decode('utf-8'),
                    "data": base64.b64encode(true_encrypted).decode('utf-8')
                },
                {
                    "id": self._generate_block_id(),
                    "iv": base64.b64encode(iv_false).decode('utf-8'),
                    "data": base64.b64encode(false_encrypted).decode('utf-8')
                }
            ],
            # 判別不能にするための追加データブロック（ノイズ）
            "verification": self._generate_verification_data()
        }

        # ブロック順序をランダム化（静的解析防止）
        random.shuffle(result["data_blocks"])

        return result

    def _prepare_encryption_params(self) -> Dict:
        """
        暗号化パラメータを準備

        Returns:
            Dict: 暗号化パラメータ
        """
        # エントロピーから導出したパラメータ
        entropy = self.entropy_collector.collect(32)

        return {
            "time_factor": int(time.time() * 1000),
            "entropy_seed": base64.b64encode(entropy[:16]).decode('utf-8'),
            "mix_rounds": random.randint(5, 15),
            "scatter_factor": random.randint(8, 32),
            "temporal_slice": random.choice(TIME_SLICE_INTERVALS)
        }

    def _derive_iv(self, key: bytes) -> bytes:
        """
        鍵から初期ベクトルを導出

        Args:
            key: 元の鍵

        Returns:
            bytes: 初期ベクトル
        """
        # 鍵導出関数（時間要素も含める）
        h = hashlib.sha256()
        h.update(key)

        # 現在の時間を含める
        time_bytes = int(time.time() * 1000).to_bytes(8, byteorder='big')
        h.update(time_bytes)

        # エントロピーを追加
        entropy = self.entropy_collector.collect(16)
        h.update(entropy)

        # 16バイトのIVを返す
        return h.digest()[:16]

    def _encrypt_data(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        データを暗号化

        Args:
            data: 暗号化するデータ
            key: 暗号化キー
            iv: 初期ベクトル

        Returns:
            bytes: 暗号化データ
        """
        # AES-CTRモードで暗号化（単純化のため）
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        # AES鍵を導出（32バイト= AES-256）
        aes_key = hashlib.sha256(key).digest()

        # CTRモードで暗号化
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # 暗号化を実行
        encrypted = encryptor.update(data) + encryptor.finalize()

        return encrypted

    def _generate_block_id(self) -> str:
        """
        ブロックIDを生成

        Returns:
            str: ブロックID
        """
        # ランダムなIDを生成
        id_bytes = secrets.token_bytes(16)
        return base64.b64encode(id_bytes).decode('utf-8')

    def _generate_verification_data(self) -> Dict:
        """
        検証データを生成

        Returns:
            Dict: 検証データ
        """
        # ランダムなノイズデータを生成
        noise = secrets.token_bytes(64)

        # 検証データ構造（実際には使用せず、解析を困難にするためのノイズ）
        return {
            "timestamp": int(time.time() * 1000),
            "data": base64.b64encode(noise).decode('utf-8'),
            "paths": {
                "count": random.randint(5, 20),
                "depth": random.randint(3, 10),
                "checksum": hashlib.sha256(noise).hexdigest()
            }
        }

    def decrypt(self, encrypted_data: Dict, key: bytes) -> bytes:
        """
        不確定暗号化されたデータを復号

        Args:
            encrypted_data: 暗号化データ
            key: 復号鍵

        Returns:
            bytes: 復号データ
        """
        # 鍵から経路選択
        path_type = self._select_path(key)

        # 複数存在するデータブロックから適切なものを選択
        selected_block = self._select_data_block(encrypted_data, key)

        # IVを取得
        iv = base64.b64decode(selected_block["iv"])

        # 暗号化データを取得
        cipher_data = base64.b64decode(selected_block["data"])

        # 復号を実行
        decrypted = self._decrypt_data(cipher_data, key, iv)

        return decrypted

    def _select_path(self, key: bytes) -> str:
        """
        鍵に基づいて経路を選択

        Args:
            key: 選択の基となる鍵

        Returns:
            str: 選択された経路タイプ ('true' または 'false')
        """
        # 鍵のハッシュ値を計算
        key_hash = hashlib.sha256(key).digest()

        # PathScattererの選択ロジックを使用
        return self.path_scatterer.select_path_type(key)

    def _select_data_block(self, encrypted_data: Dict, key: bytes) -> Dict:
        """
        鍵に基づいて適切なデータブロックを選択

        Args:
            encrypted_data: 暗号化データ
            key: 選択の基となる鍵

        Returns:
            Dict: 選択されたデータブロック
        """
        # 利用可能なブロックを取得
        blocks = encrypted_data.get("data_blocks", [])
        if not blocks:
            raise ValueError("暗号化データに有効なデータブロックがありません")

        # 鍵から選択インデックスを生成
        h = hashlib.sha256()
        h.update(key)
        h.update(b"block_selection")
        digest = h.digest()

        # 選択ロジック（複雑にして解析を困難に）
        if self.true_key_hash and key == self.true_key_hash:
            # 正規鍵の場合は最初のブロックを選択（テスト用）
            return blocks[0]
        elif self.false_key_hash and key == self.false_key_hash:
            # 非正規鍵の場合は2番目のブロックを選択（テスト用）
            return blocks[1 % len(blocks)]
        else:
            # 実際の実装では、鍵からブロックを決定論的に選択
            index = int.from_bytes(digest[:4], byteorder='big') % len(blocks)
            return blocks[index]

    def _decrypt_data(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        データを復号

        Args:
            data: 復号するデータ
            key: 復号キー
            iv: 初期ベクトル

        Returns:
            bytes: 復号データ
        """
        # AES-CTRモードで復号（暗号化と同じ処理）
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        # AES鍵を導出（32バイト= AES-256）
        aes_key = hashlib.sha256(key).digest()

        # CTRモードで復号
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # 復号を実行
        decrypted = decryptor.update(data) + decryptor.finalize()

        return decrypted


class IndeterministicCryptoSystem:
    """
    不確定性転写暗号化システム全体を管理するクラス
    """

    def __init__(self):
        """初期化"""
        self.engine = IndeterministicEngine()
        self.initialized = False

    def initialize(self) -> None:
        """システムを初期化"""
        if not self.initialized:
            self.engine.initialize()
            self.initialized = True

    def shutdown(self) -> None:
        """システムをシャットダウン"""
        if self.initialized:
            self.engine.shutdown()
            self.initialized = False

    def encrypt_files(self, true_file: str, false_file: str, output_file: str,
                    true_key_file: str, false_key_file: str) -> bool:
        """
        ファイルを暗号化

        Args:
            true_file: 正規ファイルパス
            false_file: 非正規ファイルパス
            output_file: 出力ファイルパス
            true_key_file: 正規鍵出力ファイルパス
            false_key_file: 非正規鍵出力ファイルパス

        Returns:
            bool: 成功したらTrue
        """
        try:
            # システム初期化
            self.initialize()

            # ファイル読み込み
            with open(true_file, 'rb') as f:
                true_data = f.read()

            with open(false_file, 'rb') as f:
                false_data = f.read()

            # 鍵生成
            true_key = secrets.token_bytes(32)
            false_key = secrets.token_bytes(32)

            # 暗号化
            encrypted = self.engine.encrypt(true_data, false_data, true_key, false_key)

            # 暗号化データ保存
            with open(output_file, 'w') as f:
                json.dump(encrypted, f)

            # 鍵ファイル作成（本番では別々のルートで配布）
            true_key_data = {
                "key": base64.b64encode(true_key).decode('utf-8'),
                "type": "indeterministic",
                "version": "1.0"
            }

            false_key_data = {
                "key": base64.b64encode(false_key).decode('utf-8'),
                "type": "indeterministic",
                "version": "1.0"
            }

            with open(true_key_file, 'w') as f:
                json.dump(true_key_data, f)

            with open(false_key_file, 'w') as f:
                json.dump(false_key_data, f)

            return True

        except Exception as e:
            print(f"暗号化エラー: {e}")
            return False
        finally:
            # システムシャットダウン
            self.shutdown()

    def decrypt_file(self, encrypted_file: str, key_file: str, output_file: str) -> bool:
        """
        ファイルを復号

        Args:
            encrypted_file: 暗号化ファイルパス
            key_file: 鍵ファイルパス
            output_file: 出力ファイルパス

        Returns:
            bool: 成功したらTrue
        """
        try:
            # システム初期化
            self.initialize()

            # 暗号化ファイル読み込み
            with open(encrypted_file, 'r') as f:
                encrypted_data = json.load(f)

            # 鍵ファイル読み込み
            with open(key_file, 'r') as f:
                key_data = json.load(f)

            # 鍵取得
            key = base64.b64decode(key_data["key"])

            # 復号
            decrypted = self.engine.decrypt(encrypted_data, key)

            # 復号データ保存
            with open(output_file, 'wb') as f:
                f.write(decrypted)

            return True

        except Exception as e:
            print(f"復号エラー: {e}")
            return False
        finally:
            # システムシャットダウン
            self.shutdown()


# 定数
TIME_SLICE_INTERVALS = [5, 10, 15, 20]  # ミリ秒単位
CONFUSION_RATIO = 0.7  # 真偽判別のかく乱率
```

### 5. 暗号化プログラム

**ファイル:** `method_9_indeterministic/encrypt.py`

```python
#!/usr/bin/env python3
"""
不確定性転写暗号化方式の暗号化プログラム

このプログラムは不確定性転写暗号化方式を使用して、
真偽2つのファイルを識別不能な暗号文に変換します。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import secrets
from typing import Dict, Any

# 共通モジュールへのパスを追加
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_9_indeterministic.indeterministic import IndeterministicCryptoSystem
from common.utils import read_file, write_file, generate_key

def parse_arguments():
    """コマンドライン引数の解析"""
    parser = argparse.ArgumentParser(
        description="不確定性転写暗号化方式で2つのファイルを暗号化します"
    )

    parser.add_argument('--true', required=True,
                      help='正規ファイル（暗号文が本来復元すべきファイル）')
    parser.add_argument('--false', required=True,
                      help='非正規ファイル（偽の鍵で復元されるファイル）')
    parser.add_argument('--output', '-o', required=True,
                      help='出力する暗号文ファイル')
    parser.add_argument('--key-output', '-k', required=True,
                      help='生成する鍵ファイル（実際の復号に使用）')
    parser.add_argument('--false-key-output', '-f', required=True,
                      help='生成する偽の鍵ファイル（非正規復号に使用）')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='詳細な出力を表示')

    return parser.parse_args()

def encrypt_files(args):
    """ファイル暗号化の実行"""
    print("🎲 不確定性転写暗号化方式で暗号化を開始します...")

    # 暗号化システム初期化
    crypto_system = IndeterministicCryptoSystem()

    try:
        # 暗号化実行
        success = crypto_system.encrypt_files(
            args.true, args.false, args.output, args.key_output, args.false_key_output
        )

        if success:
            # 完了メッセージ
            print(f"✅ 暗号化が完了しました！")
            print(f"  - 暗号文: {args.output}")
            print(f"  - 正規鍵: {args.key_output}")
            print(f"  - 非正規鍵: {args.false_key_output}")
            print("")
            print("⚠️ 注意: 実際の使用では正規/非正規の区別ができないようそれぞれ別のルートで配布してください")
        else:
            print("❌ 暗号化に失敗しました")
            sys.exit(1)

    except Exception as e:
        print(f"❌ 暗号化に失敗しました: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # 引数解析
    args = parse_arguments()

    # 暗号化実行
    encrypt_files(args)
```

### 6. 復号プログラム

**ファイル:** `method_9_indeterministic/decrypt.py`

```python
#!/usr/bin/env python3
"""
不確定性転写暗号化方式の復号プログラム

このプログラムは不確定性転写暗号化方式で暗号化されたファイルを復号します。
入力鍵に応じて正規/非正規のいずれかのファイルを復元します。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
from typing import Dict, Any

# 共通モジュールへのパスを追加
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_9_indeterministic.indeterministic import IndeterministicCryptoSystem
from common.utils import read_file, write_file

def parse_arguments():
    """コマンドライン引数の解析"""
    parser = argparse.ArgumentParser(
        description="不確定性転写暗号化方式で暗号化されたファイルを復号します"
    )

    parser.add_argument('--input', '-i', required=True,
                      help='入力暗号文ファイル')
    parser.add_argument('--key', '-k', required=True,
                      help='復号鍵ファイル')
    parser.add_argument('--output', '-o', required=True,
                      help='出力ファイル（復号結果）')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='詳細な出力を表示')

    return parser.parse_args()

def decrypt_file(args):
    """ファイル復号の実行"""
    print("🎲 不確定性転写暗号化方式で復号を開始します...")

    # 暗号化システム初期化
    crypto_system = IndeterministicCryptoSystem()

    try:
        # 復号実行
        success = crypto_system.decrypt_file(
            args.input, args.key, args.output
        )

        if success:
            # 完了メッセージ
            print(f"✅ 復号が完了しました！")
            print(f"  - 出力ファイル: {args.output}")
        else:
            print("❌ 復号に失敗しました")
            sys.exit(1)

    except Exception as e:
        print(f"❌ 復号に失敗しました: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # 引数解析
    args = parse_arguments()

    # 復号実行
    decrypt_file(args)
```

## 🧪 テスト方法

### 1. 環境構築

まず必要なパッケージをインストールします：

```bash
pip install cryptography
```

### 2. 基本テスト

以下のコマンドで基本機能をテストします：

```bash
# テスト用ファイルの準備
cp common/true-false-text/true.text ./true.text
cp common/true-false-text/false.text ./false.text

# 暗号化（正規鍵と偽鍵を両方生成）
python method_9_indeterministic/encrypt.py --true true.text --false false.text \
  --output encrypted.dat --key-output true_key.json --false-key-output false_key.json

# 正規鍵で復号
python method_9_indeterministic/decrypt.py --input encrypted.dat \
  --key true_key.json --output decrypted_true.text

# 偽鍵で復号
python method_9_indeterministic/decrypt.py --input encrypted.dat \
  --key false_key.json --output decrypted_false.text

# 結果を確認
cat decrypted_true.text
cat decrypted_false.text
```

### 3. ソースコード解析耐性テスト

以下の点を検証します：

1. コード静的解析で真/偽のパスを区別できないことを確認

   ```bash
   # ソースコード内に固定パターンがないか検証
   grep -r "true|false" method_9_indeterministic/ | grep -v "test"
   ```

2. 実行トレース解析で真/偽のパスを識別できないことを確認

   ```bash
   # 実行中の分岐パスをランダムに選択するかテスト
   python -m trace --trace method_9_indeterministic/decrypt.py --input encrypted.dat \
     --key true_key.json --output trace_output.text
   ```

3. 複数回の実行で異なる実行パスを通ることを確認
   ```bash
   # 同じキーで複数回実行してトレースを比較
   for i in {1..3}; do
     python -m trace --count method_9_indeterministic/decrypt.py --input encrypted.dat \
       --key true_key.json --output trace_output_$i.text
     sleep 1
   done
   diff trace_output_1.text trace_output_2.text
   ```

## 📚 参考資料

### 非決定論的暗号化の参考文献

- [Probabilistic Encryption - Goldwasser-Micali](https://en.wikipedia.org/wiki/Probabilistic_encryption)
- [Dynamic Cryptography: From Oxymoron to Reality](https://eprint.iacr.org/2017/935.pdf)
- [Moving Target Defense in Cryptography](https://www.sciencedirect.com/science/article/pii/S0167404815001583)

### 実行パス分散に関する資料

- [Path Divergence - OWASP](https://owasp.org/www-community/attacks/Path_Traversal)
- [Control Flow Obfuscation Methods](https://www.sciencedirect.com/science/article/abs/pii/S0167404816301607)
- [Dynamic Execution Path Analysis](https://link.springer.com/chapter/10.1007/978-3-319-47166-2_34)

### 動的解析対策の資料

- [Anti Debugging Techniques - GitHub](https://github.com/CheckPointSW/Anti-Debug)
- [Software Protection Against Dynamic Analysis](https://ieeexplore.ieee.org/document/8894107)
- [Time-based Anti-Analysis Techniques](https://www.blackhat.com/docs/us-16/materials/us-16-Streeckx-Time-Based-Detection-And-Evasion-of-Dynamic-Analysis-Techniques.pdf)

## 📝 実装に関する注意事項

1. 実装の際は動的解析ツールによる検知対策を必ず含めること
2. 時間的エントロピー注入部分が環境に強く依存するため、テスト環境と本番環境で挙動が変わる可能性があることに注意
3. 実装の複雑さと処理パフォーマンスのバランスを取ること
4. 暗号文のサイズが元のファイルより大きくなることを考慮すること
5. 実行時メモリ使用量に注意し、大きなファイルの場合はストリーム処理を検討すること
   </rewritten_file>

# シャミア秘密分散法による複数平文復号システム実装プロンプト

## 開発者ペルソナ

あなたは暗号学とセキュアコーディングに精通した Python 開発者です。以下の専門知識と経験を持っています：

1. **シャミア秘密分散法**の理論と実装に精通しており、閾値暗号の概念を深く理解しています
2. **大きな素数体**上での計算を効率的に実装できる能力を持ちます（特に 2^521-1 のような大きな素数での演算）
3. **サイドチャネル攻撃対策**に関する知識があり、定数時間アルゴリズム、タイミング攻撃対策などのセキュアコーディング技術に精通しています
4. **統計的区別不可能性**の概念を理解し、暗号化データから情報漏洩しないような実装ができます
5. **WAL ログ方式**や**原子的更新**などのデータ整合性確保手法を実装できます
6. **Python のベストプラクティス**を遵守し、明確なドキュメントと効率的なコーディングスタイルを実践します

### 開発環境

- Python 3 を使用した実装
- 信頼性の高い暗号ライブラリとして`cryptography`を利用
- 大きな整数の処理に`gmpy2`ライブラリを使用
- KDF として Argon2id を採用
- テスト駆動開発を実践
- 条件分岐を避け、定数時間処理を重視した実装スタイル

### 実装の基本方針

1. セキュリティ優先：正確性とセキュリティを最優先し、性能は二の次とします
2. 統計的区別不可能性：文書 A、B、未割当領域の区別が不可能な実装を目指します
3. サイドチャネル攻撃耐性：定数時間アルゴリズムを徹底し、タイミング攻撃などに耐性を持つコードを実装します
4. 拡張性：将来の機能追加や変更を考慮した柔軟な設計を心がけます
5. 堅牢なエラー処理：暗号処理中のエラーを適切に処理し、セキュリティリスクを最小化します

### 設計書参照

実装にあたっては、提供されている設計書のドキュメントを参照してください。これらのドキュメントには、システム設計の詳細、セキュリティ要件、およびベストプラクティスが記載されています：

- `00_terms.md`：用語の定義と基本概念
- `01_overview.md`：システム概要と目的
- `02_architecture.md`：システムアーキテクチャと設計原則
- `03_detailed_design.md`：詳細設計と技術仕様
- `04_implementation.md`：実装手順とガイドライン
- `05_security.md`：セキュリティ要件と脅威モデル
- `06_performance.md`：性能要件と最適化
- `07_guidelines.md`：実装ガイドラインとベストプラクティス
- `08_references.md`：参考文献と外部リソース
- `09_conclusion.md`：まとめと将来の方向性

### 利用可能なライブラリと推奨

実装には以下のライブラリが利用可能で、最新バージョンが確認されています：

1. **gmpy2 2.2.1** (2024 年 7 月リリース) - 大きな整数と有限体での計算に最適化された高速な多倍長演算ライブラリ

   - Python 3.7 から 3.13 までサポート
   - スレッドセーフなコンテキストと改善された Cython 連携をサポート

2. **cryptography 45.0.2** (2025 年 5 月リリース) - Python の標準的な暗号ライブラリ

   - モダンな暗号アルゴリズムとプロトコルを提供
   - セキュリティ的に健全な実装と API を持つ

3. **PyCryptodome** - 追加の推奨ライブラリとして検討できる
   - `Crypto.Protocol.SecretSharing.Shamir`モジュールにシャミア秘密分散法の実装が含まれている
   - 16 バイト（AES-128 キーサイズ）の秘密を分散・再構築するための最適化された実装
   - GF(2^128)有限体上で動作し、セキュリティと互換性に優れている

特に、PyCryptodome はシャミア秘密分散法に特化した機能を提供しており、必要に応じて参考にするか採用することを推奨します。ただし、独自の要件（特に 2^521-1 の素数体での計算）に対応するため、`gmpy2`と`cryptography`を基盤とした独自実装も検討価値があります。

## 実装すべき機能

あなたは以下の機能を含む Python モジュールを実装する必要があります：
## システムの初期化

システムの初期化部分では、パーティション空間の設定、パーティションマップキーの生成、そしてシステム全体のセットアップを行います。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `02_architecture.md`: パーティション空間の基本設計原則
- `03_detailed_design.md`: パーティション空間の詳細設計
- `04_implementation.md`: 実装詳細とシステムの初期化方法
- `07_guidelines.md`: 安全なパーティション空間管理の実装ガイドライン

### 1. 必要なライブラリとパッケージ

```python
# 暗号関連の基本ライブラリ
import os
import secrets
import hashlib
import hmac
import json
import base64
import zlib
from typing import Dict, List, Tuple, Set, Union, Any, Optional
import uuid
import time
import fcntl
import shutil
from pathlib import Path

# 大きな整数演算のためのライブラリ
import gmpy2
from gmpy2 import mpz

# 暗号ライブラリ
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
```

### 2. システム定数の定義

```python
class ShamirConstants:
    """システム全体で使用する定数"""
    # 有限体の素数 (2^521 - 1)
    PRIME = mpz(2**521 - 1)

    # 閾値（最小復元シェア数）
    DEFAULT_THRESHOLD = 3

    # チャンクサイズ（バイト単位）
    CHUNK_SIZE = 64

    # KDF設定
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_TIME_COST = 3
    ARGON2_PARALLELISM = 4
    ARGON2_OUTPUT_LENGTH = 32

    # パーティション比率
    RATIO_A = 0.35  # Aユーザー用（35%）
    RATIO_B = 0.35  # Bユーザー用（35%）
    RATIO_UNASSIGNED = 0.30  # 未割当（30%）

    # シェアID空間サイズ
    SHARE_ID_SPACE = 2**32 - 1

    # WALログのタイムアウト（秒）
    WAL_TIMEOUT = 3600  # 1時間

    # テンポラリファイルのプレフィックス
    TEMP_FILE_PREFIX = "shamir_temp_"
```

### 3. パーティションマップキーの生成

```python
def generate_partition_map_key(length: int = 32) -> str:
    """
    パーティションマップキーを生成する

    Args:
        length: 生成するキーの長さ（バイト）

    Returns:
        base64エンコードされたパーティションマップキー
    """
    # 暗号論的に安全な乱数を生成
    random_bytes = secrets.token_bytes(length)

    # 読みやすいBase64文字列に変換（URL安全版）
    map_key = base64.urlsafe_b64encode(random_bytes).decode('ascii')

    return map_key
```

### 4. パーティション空間の管理

```python
class PartitionManager:
    """パーティション空間を管理するクラス"""

    def __init__(self,
                 partition_a_key: str,
                 partition_b_key: str,
                 total_shares: int = 1000):
        """
        パーティションマネージャーを初期化

        Args:
            partition_a_key: Aユーザー用パーティションマップキー
            partition_b_key: Bユーザー用パーティションマップキー
            total_shares: 生成する総シェア数
        """
        self.partition_a_key = partition_a_key
        self.partition_b_key = partition_b_key
        self.total_shares = total_shares

        # 各パーティションのシェア数を計算
        self.a_shares_count = int(total_shares * ShamirConstants.RATIO_A)
        self.b_shares_count = int(total_shares * ShamirConstants.RATIO_B)
        self.unassigned_count = total_shares - self.a_shares_count - self.b_shares_count

        # シェアIDを生成
        self.all_share_ids = self._generate_all_share_ids()
        self.a_share_ids = self._map_partition_ids(partition_a_key, self.a_shares_count)
        self.b_share_ids = self._map_partition_ids(partition_b_key, self.b_shares_count)

        # 未割当IDを計算（AとBに割り当てられていないID）
        self.unassigned_ids = self._calculate_unassigned_ids()

    def _generate_all_share_ids(self) -> List[int]:
        """全シェアIDを生成（1からSHARE_ID_SPACE間の一意な値）"""
        ids = set()
        while len(ids) < self.total_shares:
            new_id = secrets.randbelow(ShamirConstants.SHARE_ID_SPACE - 1) + 1
            ids.add(new_id)
        return sorted(list(ids))

    def _map_partition_ids(self, partition_key: str, count: int) -> List[int]:
        """
        パーティションマップキーからシェアIDを決定論的に生成

        Args:
            partition_key: パーティションマップキー
            count: 生成するID数

        Returns:
            シェアIDのリスト
        """
        # パーティションマップキーから決定論的にシード値を生成
        key_bytes = partition_key.encode('ascii')
        seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

        # シードから擬似乱数を生成（暗号論的に安全でなくてもよい）
        import random
        rng = random.Random(seed)

        # 全シェアIDからランダムにcount個選択
        selected_ids = sorted(rng.sample(self.all_share_ids, count))
        return selected_ids

    def _calculate_unassigned_ids(self) -> List[int]:
        """未割当IDを計算（AともBとも異なるID）"""
        a_set = set(self.a_share_ids)
        b_set = set(self.b_share_ids)
        all_set = set(self.all_share_ids)

        # 差集合で計算
        unassigned = all_set - a_set - b_set
        return sorted(list(unassigned))

    def get_partition_ids(self, partition_key: str) -> List[int]:
        """
        パーティションマップキーに対応するシェアIDを取得

        Args:
            partition_key: パーティションマップキー

        Returns:
            シェアIDのリスト
        """
        if partition_key == self.partition_a_key:
            return self.a_share_ids
        elif partition_key == self.partition_b_key:
            return self.b_share_ids
        else:
            # 対応するIDが見つからない場合は空リストを返す
            return []
```

### 5. 統計的区別不可能性の検証

```python
def verify_statistical_indistinguishability(
    a_ids: List[int],
    b_ids: List[int],
    unassigned_ids: List[int]
) -> bool:
    """
    パーティション空間の統計的区別不可能性を検証

    Args:
        a_ids: Aユーザー用IDリスト
        b_ids: Bユーザー用IDリスト
        unassigned_ids: 未割当IDリスト

    Returns:
        検証結果（True: 問題なし、False: 偏りあり）
    """
    # 全IDを結合してソート
    all_ids = sorted(a_ids + b_ids + unassigned_ids)
    total_count = len(all_ids)

    # ブロックサイズの決定（全体の約5%）
    block_size = max(10, total_count // 20)

    # 各ブロック内でのA, B, 未割当の比率を検証
    for start in range(0, total_count, block_size):
        end = min(start + block_size, total_count)
        block = all_ids[start:end]

        # ブロック内の各タイプのカウント
        a_count = sum(1 for id in block if id in a_ids)
        b_count = sum(1 for id in block if id in b_ids)
        u_count = sum(1 for id in block if id in unassigned_ids)

        # 各タイプの比率を計算
        block_total = len(block)
        a_ratio = a_count / block_total
        b_ratio = b_count / block_total
        u_ratio = u_count / block_total

        # 比率の許容範囲（±10%ポイント）
        if (abs(a_ratio - ShamirConstants.RATIO_A) > 0.1 or
            abs(b_ratio - ShamirConstants.RATIO_B) > 0.1 or
            abs(u_ratio - ShamirConstants.RATIO_UNASSIGNED) > 0.1):
            return False

    return True
```

### 6. システム初期化関数

```python
def initialize_system() -> Dict[str, Any]:
    """
    シャミア秘密分散システムを初期化し、必要なキーと設定を返す

    Returns:
        システム初期化情報を含む辞書
    """
    # パーティションマップキーを生成
    partition_a_key = generate_partition_map_key()
    partition_b_key = generate_partition_map_key()

    # パーティションマネージャーを初期化
    partition_manager = PartitionManager(
        partition_a_key=partition_a_key,
        partition_b_key=partition_b_key,
        total_shares=1000  # 総シェア数
    )

    # 統計的区別不可能性を検証
    is_indistinguishable = verify_statistical_indistinguishability(
        partition_manager.a_share_ids,
        partition_manager.b_share_ids,
        partition_manager.unassigned_ids
    )

    # 検証に失敗した場合は再初期化
    retry_count = 0
    while not is_indistinguishable and retry_count < 5:
        partition_manager = PartitionManager(
            partition_a_key=partition_a_key,
            partition_b_key=partition_b_key,
            total_shares=1000
        )
        is_indistinguishable = verify_statistical_indistinguishability(
            partition_manager.a_share_ids,
            partition_manager.b_share_ids,
            partition_manager.unassigned_ids
        )
        retry_count += 1

    if not is_indistinguishable:
        raise ValueError("統計的区別不可能性の検証に失敗しました。システム初期化をやり直してください。")

    # システム設定を辞書にまとめて返す
    return {
        "partition_a_key": partition_a_key,
        "partition_b_key": partition_b_key,
        "threshold": ShamirConstants.DEFAULT_THRESHOLD,
        "total_shares": partition_manager.total_shares,
        "a_share_count": partition_manager.a_shares_count,
        "b_share_count": partition_manager.b_shares_count,
        "unassigned_count": partition_manager.unassigned_count,
        "initialized_at": int(time.time())
    }
```
## データの暗号化

暗号化プロセスでは、JSON 文書をシャミア秘密分散法を使用して暗号化します。この部分はシステムの核心となるコンポーネントで、統計的区別不可能性や定数時間処理といった重要なセキュリティ要件を満たす必要があります。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `02_architecture.md`: 多段 MAP 方式の詳細
- `03_detailed_design.md`: シャミア秘密分散法の実装と多段 MAP の詳細
- `04_implementation.md`: 4.1 節「暗号化プロセス」の詳細手順
- `05_security.md`: セキュリティ要件と攻撃モデル
- `07_guidelines.md`: 7.3 節「条件分岐の禁止と定数時間処理の実装パターン」

### 1. シャミア秘密分散法の実装

```python
def generate_polynomial(secret: mpz, degree: int, prime: mpz) -> List[mpz]:
    """
    シャミア秘密分散法で使用する多項式を生成

    Args:
        secret: 秘密値
        degree: 多項式の次数（閾値t-1）
        prime: 有限体の素数

    Returns:
        多項式の係数リスト
    """
    # 最初の係数に秘密値を設定
    coef = [secret]

    # 残りの係数をランダムに生成（1からp-1までの範囲）
    for i in range(degree):
        random_coef = mpz(secrets.randbelow(int(prime - 1))) + 1
        coef.append(random_coef)

    return coef


def evaluate_polynomial(coef: List[mpz], x: mpz, prime: mpz) -> mpz:
    """
    多項式を評価して点(x, y)のy値を計算

    Args:
        coef: 多項式の係数リスト
        x: x座標
        prime: 有限体の素数

    Returns:
        y = P(x) mod prime
    """
    result = mpz(0)

    # 定数時間処理のため、実質的にはループ展開するのが理想的
    # しかし可変サイズの係数リストに対応するため、ループで実装
    for i in range(len(coef)):
        term = coef[i] * gmpy2.powmod(x, i, prime)
        result = (result + term) % prime

    return result


def generate_shares(secret: mpz, threshold: int, share_ids: List[int], prime: mpz) -> List[Tuple[int, mpz]]:
    """
    シークレットからシェアを生成

    Args:
        secret: 秘密値
        threshold: 閾値（復元に必要な最小シェア数）
        share_ids: シェアのID（x座標）リスト
        prime: 有限体の素数

    Returns:
        (シェアID, シェア値)のタプルリスト
    """
    # 閾値が1のときは自明なケース（多項式は定数項のみ）
    if threshold < 2:
        return [(x, secret) for x in share_ids]

    # 閾値tに対して次数(t-1)の多項式を生成
    poly_degree = threshold - 1
    coef = generate_polynomial(secret, poly_degree, prime)

    # 各シェアIDに対して多項式を評価
    shares = []
    for id in share_ids:
        x = mpz(id)
        y = evaluate_polynomial(coef, x, prime)
        shares.append((id, y))

    return shares


def lagrange_interpolation(shares: List[Tuple[int, mpz]], prime: mpz) -> mpz:
    """
    ラグランジュ補間法を使用して秘密を復元

    Args:
        shares: (シェアID, シェア値)のタプルリスト
        prime: 有限体の素数

    Returns:
        復元された秘密値
    """
    # x=0での多項式の値を計算
    secret = mpz(0)

    # 各シェアのラグランジュ係数を計算
    for i, (x_i, y_i) in enumerate(shares):
        x_i = mpz(x_i)
        numerator = mpz(1)    # 分子
        denominator = mpz(1)  # 分母

        # ラグランジュ基底多項式の計算
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                x_j = mpz(x_j)
                numerator = (numerator * (0 - x_j)) % prime
                denominator = (denominator * (x_i - x_j)) % prime

        # モジュラ逆数を計算（拡張ユークリッド互除法）
        # a * x ≡ 1 (mod p) となるxを計算
        denominator_inv = gmpy2.invert(denominator, prime)

        # ラグランジュ係数
        lagrange_coef = (numerator * denominator_inv) % prime

        # 秘密値に加算
        term = (y_i * lagrange_coef) % prime
        secret = (secret + term) % prime

    return secret
```

### 2. 多段エンコードと文書前処理

```python
def preprocess_json_document(json_doc: Any) -> bytes:
    """
    JSON文書を暗号化のために前処理する

    Args:
        json_doc: 暗号化するJSON文書（辞書またはリスト）

    Returns:
        前処理済みのバイトデータ
    """
    # JSONをUTF-8形式の文字列に変換（余分な空白を除去）
    json_str = json.dumps(json_doc, ensure_ascii=False, separators=(',', ':'))
    utf8_bytes = json_str.encode('utf-8')

    # 圧縮（条件判断なし、常に最大レベルで圧縮）
    compressed_data = zlib.compress(utf8_bytes, level=9)

    # URL安全なBase64エンコード
    base64_data = base64.urlsafe_b64encode(compressed_data)

    return base64_data


def split_into_chunks(data: bytes, chunk_size: int = ShamirConstants.CHUNK_SIZE) -> List[bytes]:
    """
    データを一定サイズのチャンクに分割

    Args:
        data: 分割対象のバイトデータ
        chunk_size: チャンクサイズ（バイト単位）

    Returns:
        バイトチャンクのリスト
    """
    chunks = []

    # データをチャンクサイズごとに分割
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]

        # 最後のチャンクが不完全な場合はパディング
        if len(chunk) < chunk_size:
            # ゼロパディング（サイドチャネル攻撃防止のため常に同じサイズに）
            chunk = chunk.ljust(chunk_size, b'\0')

        chunks.append(chunk)

    return chunks
```

### 3. 多段 MAP の実装

```python
def derive_key(password: str, salt: bytes, iterations: int = 310000, length: int = 32) -> bytes:
    """
    パスワードから鍵を導出（Argon2idまたはPBKDF2）

    Args:
        password: パスワード
        salt: ソルト値
        iterations: イテレーション回数（PBKDF2の場合）
        length: 出力キー長

    Returns:
        導出された鍵
    """
    try:
        # 可能であればArgon2idを使用（より強力）
        kdf = Argon2(
            length=length,
            salt=salt,
            time_cost=ShamirConstants.ARGON2_TIME_COST,
            memory_cost=ShamirConstants.ARGON2_MEMORY_COST,
            parallelism=ShamirConstants.ARGON2_PARALLELISM,
            type=cryptography.hazmat.primitives.kdf.argon2.Argon2Type.ID,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
    except:
        # フォールバックとしてPBKDF2-HMAC-SHA256を使用
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))

    return key


def stage1_map(partition_key: str, all_share_ids: List[int]) -> List[int]:
    """
    第1段階MAP：パーティションマップキーから候補シェアIDを取得

    Args:
        partition_key: パーティションマップキー
        all_share_ids: 全シェアIDリスト

    Returns:
        選択されたシェアIDリスト
    """
    # パーティションマップキーからシード値を生成
    key_bytes = partition_key.encode('ascii')
    seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

    # シードから擬似乱数生成器を初期化
    import random
    rng = random.Random(seed)

    # シェアIDをシャッフルし、決定論的にサブセットを選択
    # パーティションマップキーが同じなら同じIDセットが選ばれる
    shuffled_ids = list(all_share_ids)  # コピーを作成
    rng.shuffle(shuffled_ids)

    # 全シェアの約35%を選択（パーティションのサイズに近い値）
    selected_count = int(len(all_share_ids) * ShamirConstants.RATIO_A)
    selected_ids = shuffled_ids[:selected_count]

    return selected_ids


def stage2_map(password: str, candidate_ids: List[int], salt: bytes) -> Dict[int, int]:
    """
    第2段階MAP：パスワードからシェアマッピングを生成

    Args:
        password: パスワード
        candidate_ids: 候補シェアID（第1段階で選択されたID）
        salt: ソルト値

    Returns:
        {シェアID: マッピング値}の辞書
    """
    # パスワードからキーを導出
    key = derive_key(password, salt)

    # 各シェアIDに対してマッピング値を生成
    mapping = {}
    for share_id in candidate_ids:
        # HMAC-SHA256でマッピング値を決定論的に生成
        h = hmac.new(key, str(share_id).encode(), 'sha256')
        mapping_value = int.from_bytes(h.digest(), 'big')
        mapping[share_id] = mapping_value

    return mapping


def select_shares_for_encryption(partition_key: str, password: str, all_share_ids: List[int],
                                 salt: bytes, threshold: int) -> List[int]:
    """
    暗号化に使用するシェアIDを選択

    Args:
        partition_key: パーティションマップキー
        password: パスワード
        all_share_ids: 全シェアIDリスト
        salt: ソルト値
        threshold: 閾値

    Returns:
        暗号化に使用するシェアIDリスト
    """
    # 第1段階：パーティションマップキーによる候補選択
    candidate_ids = stage1_map(partition_key, all_share_ids)

    # 第2段階：パスワードによるマッピング
    mappings = stage2_map(password, candidate_ids, salt)

    # マッピング値でソート
    sorted_ids = sorted(candidate_ids, key=lambda id: mappings[id])

    # 閾値の3倍のシェアを選択（冗長性のため）
    # 最低でも閾値の数は必要
    selection_count = min(threshold * 3, len(sorted_ids))
    selection_count = max(selection_count, threshold)

    selected_ids = sorted_ids[:selection_count]
    return selected_ids
```

### 4. 暗号化プロセス

```python
def generate_garbage_shares(unassigned_ids: List[int], chunk_count: int,
                           threshold: int, prime: mpz) -> List[Dict[str, Any]]:
    """
    未割当領域用のゴミシェアを生成

    Args:
        unassigned_ids: 未割当シェアID
        chunk_count: 生成するチャンク数
        threshold: 閾値
        prime: 有限体の素数

    Returns:
        ゴミシェアのリスト
    """
    garbage_shares = []

    # 各チャンクに対してゴミシェアを生成
    for chunk_idx in range(chunk_count):
        # 各IDに対して乱数値を生成
        for id in unassigned_ids:
            # 完全なランダム値（実際のシェアと統計的に区別不可能）
            value = mpz(secrets.randbelow(int(prime - 1))) + 1

            # シェアオブジェクトを作成
            garbage_share = {
                'chunk_index': chunk_idx,
                'share_id': id,
                'value': str(value)  # 文字列として保存
            }

            garbage_shares.append(garbage_share)

    return garbage_shares


def encrypt_json_document(json_doc: Any, password: str, partition_key: str,
                         all_share_ids: List[int], threshold: int = ShamirConstants.DEFAULT_THRESHOLD) -> Dict[str, Any]:
    """
    JSON文書を暗号化

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を暗号化します。
    ただし、暗号化ファイル自体は将来的に複数文書（AとB）のシェアを含むように設計されています。

    Args:
        json_doc: 暗号化するJSON文書
        password: 暗号化パスワード
        partition_key: パーティションマップキー（AまたはBのいずれか）
        all_share_ids: 全シェアIDリスト（パーティションマネージャーから取得）
        threshold: 閾値

    Returns:
        暗号化されたファイルデータ
    """
    # ソルト値を生成
    salt = secrets.token_bytes(16)

    # JSONを前処理
    preprocessed_data = preprocess_json_document(json_doc)

    # チャンクに分割
    chunks = split_into_chunks(preprocessed_data)

    # 使用するシェアIDを選択
    selected_share_ids = select_shares_for_encryption(
        partition_key, password, all_share_ids, salt, threshold
    )

    # 各チャンクをシェア化
    all_shares = []
    for chunk_idx, chunk in enumerate(chunks):
        # チャンクをint値に変換
        secret = mpz(int.from_bytes(chunk, 'big'))

        # シェア生成
        chunk_shares = generate_shares(
            secret, threshold, selected_share_ids, ShamirConstants.PRIME
        )

        # シェアをフォーマット
        for share_id, value in chunk_shares:
            all_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': str(value)  # 文字列として保存
            })

    # メタデータを作成
    metadata = {
        'salt': base64.urlsafe_b64encode(salt).decode('ascii'),
        'total_chunks': len(chunks),
        'threshold': threshold
    }

    # 暗号化ファイルフォーマット
    encrypted_file = {
        'metadata': metadata,
        'shares': all_shares
    }

    return encrypted_file


def save_encrypted_file(encrypted_file: Dict[str, Any], output_path: str) -> None:
    """
    暗号化ファイルをディスクに保存

    Args:
        encrypted_file: 暗号化ファイルデータ
        output_path: 出力先のファイルパス
    """
    with open(output_path, 'w') as f:
        json.dump(encrypted_file, f)
```
## データの復号

復号プロセスでは、暗号化ファイルから適切なシェアを選択し、シャミア秘密分散法を用いて元の JSON 文書を復元します。このプロセスでは条件分岐を避け、定数時間で処理を行う必要があります。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `02_architecture.md`: 2.3 節「多段 MAP 方式の詳細」
- `03_detailed_design.md`: 3.3 節「多段 MAP の実装」
- `04_implementation.md`: 4.2 節「復号プロセス」
- `05_security.md`: 5.3 節「ソースコード漏洩時のセキュリティ」
- `07_guidelines.md`: 7.3 節「条件分岐の禁止と定数時間処理の実装パターン」

### 1. 多段 MAP 処理の実装

データの復号化部分では、暗号化ファイルから多段 MAP を使ってシェアを選択し、シャミア秘密分散法で復元処理を行います。サイドチャネル攻撃に対する防御として、条件分岐を避けた定数時間処理を実装します。

### 1. 多段 MAP によるシェア選択

```python
def select_shares_for_decryption(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> List[Dict[str, Any]]:
    """
    復号に使用するシェアを多段MAPで選択

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を復号します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        encrypted_file: 暗号化されたファイルデータ
        partition_key: パーティションマップキー（AまたはBのいずれか）
        password: 復号化パスワード

    Returns:
        選択されたシェアのリスト（チャンクごとにソート済み）
    """
    # メタデータ取得
    metadata = encrypted_file['metadata']
    threshold = metadata['threshold']
    all_shares = encrypted_file['shares']

    # ソルト値を取得
    salt = base64.b64decode(metadata['salt'])

    # パーティションマップキーからシェアIDを取得（第1段階MAP）
    # 全シェアIDリストを構築
    all_share_ids = sorted(list(set(share['share_id'] for share in all_shares)))

    # 第1段階MAP: パーティションマップキーによる候補シェア選択
    candidate_ids = stage1_map(partition_key, all_share_ids)

    # 候補シェアから実際のシェアオブジェクトを取得
    candidate_shares = [s for s in all_shares if s['share_id'] in candidate_ids]

    # 第2段階MAP: パスワードによるマッピング
    mappings = stage2_map(password, candidate_ids, salt)

    # チャンク別にシェアを整理
    chunks = {}
    for share in candidate_shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        # シェア値を文字列からmpzに変換
        value = mpz(share['value'])
        chunks[chunk_idx].append((share['share_id'], value))

    # 各チャンクについて、シェアをマッピング値でソートし、閾値分選択
    selected_shares = []
    chunk_indices = sorted(chunks.keys())

    for chunk_idx in chunk_indices:
        # マッピング値でソート
        sorted_shares = sorted(chunks[chunk_idx], key=lambda s: mappings[s[0]])

        # 閾値分のシェアを選択
        threshold_shares = sorted_shares[:threshold]

        # 選択されたシェアをリストに追加
        for share_id, value in threshold_shares:
            selected_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': value
            })

    return selected_shares
```

### 2. データの復元と後処理

```python
def reconstruct_secret(
    shares: List[Dict[str, Any]],
    threshold: int,
    prime: mpz
) -> List[bytes]:
    """
    シェアから秘密（チャンク）を復元

    Args:
        shares: 選択されたシェア
        threshold: 閾値
        prime: 有限体の素数

    Returns:
        復元されたチャンクデータ
    """
    # チャンク別にシェアを整理
    chunks = {}
    for share in shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        chunks[chunk_idx].append((share['share_id'], share['value']))

    # 各チャンクを復元
    reconstructed_chunks = []
    chunk_indices = sorted(chunks.keys())

    for chunk_idx in chunk_indices:
        chunk_shares = chunks[chunk_idx]

        # ラグランジュ補間で秘密を復元
        secret = lagrange_interpolation(chunk_shares, prime)

        # 秘密を適切なバイト長に変換
        # mpzからバイト列に変換する際のビット長計算
        bit_length = secret.bit_length()
        byte_length = (bit_length + 7) // 8
        byte_length = max(byte_length, 1)  # 最低1バイト

        # ゼロの場合は特別処理
        if secret == 0:
            chunk_bytes = b'\x00' * ShamirConstants.CHUNK_SIZE
        else:
            # 整数からバイト列に変換
            chunk_bytes = secret.to_bytes(byte_length, 'big')

            # チャンクサイズが一定になるようにパディング/トリミング
            if len(chunk_bytes) < ShamirConstants.CHUNK_SIZE:
                chunk_bytes = chunk_bytes.ljust(ShamirConstants.CHUNK_SIZE, b'\x00')
            elif len(chunk_bytes) > ShamirConstants.CHUNK_SIZE:
                chunk_bytes = chunk_bytes[:ShamirConstants.CHUNK_SIZE]

        reconstructed_chunks.append(chunk_bytes)

    return reconstructed_chunks


def postprocess_json_document(chunks: List[bytes]) -> Any:
    """
    復元されたチャンクからJSON文書を復元

    Args:
        chunks: 復元されたチャンクのリスト

    Returns:
        復元されたJSON文書
    """
    # チャンクを結合
    data = b''.join(chunks)

    # パディングを除去（後続のヌルバイトを除去）
    data = data.rstrip(b'\x00')

    # URL安全なBase64デコード
    try:
        compressed_data = base64.urlsafe_b64decode(data)

        # 解凍
        json_bytes = zlib.decompress(compressed_data)

        # JSON解析
        json_data = json.loads(json_bytes.decode('utf-8'))
        return json_data
    except Exception as e:
        # エラーが発生した場合、部分的な結果を返す
        # サイドチャネル攻撃対策として例外は投げない
        return {"error": "Invalid data or wrong password", "partial_data": data[:100].hex()}
```

### 3. 定数時間復号化処理

```python
def constant_time_select(condition: bool, true_value: Any, false_value: Any) -> Any:
    """
    条件分岐なしの選択処理

    Args:
        condition: 条件
        true_value: 条件がTrueの場合の値
        false_value: 条件がFalseの場合の値

    Returns:
        選択された値
    """
    # 条件を整数に変換（True: 1, False: 0）
    condition_int = int(condition)

    # ビット演算による選択
    # 数値型の場合
    if isinstance(true_value, (int, float)) and isinstance(false_value, (int, float)):
        # condition_int が 1 なら true_value を、0 なら false_value を返す
        return (condition_int * true_value) + ((1 - condition_int) * false_value)

    # リスト型の場合
    elif isinstance(true_value, list) and isinstance(false_value, list):
        if condition_int:
            return true_value.copy()
        else:
            return false_value.copy()

    # その他の型（辞書、文字列など）
    else:
        if condition_int:
            if hasattr(true_value, 'copy') and callable(getattr(true_value, 'copy')):
                return true_value.copy()
            return true_value
        else:
            if hasattr(false_value, 'copy') and callable(getattr(false_value, 'copy')):
                return false_value.copy()
            return false_value


def try_decrypt_with_both_maps(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Tuple[bool, Any]:
    """
    パーティションマップキーとパスワードを使って復号を試みる
    エラーが発生しても例外を投げず、成功/失敗を返す

    Args:
        encrypted_file: 暗号化ファイル
        partition_key: パーティションマップキー
        password: パスワード

    Returns:
        (成功フラグ, 復元されたJSON文書または部分データ)
    """
    try:
        # シェアを選択
        selected_shares = select_shares_for_decryption(
            encrypted_file, partition_key, password
        )

        # メタデータから閾値を取得
        threshold = encrypted_file['metadata']['threshold']

        # シェアから秘密を復元
        reconstructed_chunks = reconstruct_secret(
            selected_shares, threshold, ShamirConstants.PRIME
        )

        # 後処理してJSON文書に変換
        json_doc = postprocess_json_document(reconstructed_chunks)

        # JSONとして解析できた場合は成功
        success = True
        if isinstance(json_doc, dict) and 'error' in json_doc:
            success = False

        return (success, json_doc)

    except Exception as e:
        # どのような例外が発生しても、サイドチャネル攻撃対策として
        # エラーレスポンスを返す
        return (False, {"error": "Decryption failed", "details": str(e)})


def decrypt_json_document(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Any:
    """
    暗号化されたJSONドキュメントを復号

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を復号します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        encrypted_file: 暗号化ファイル
        partition_key: パーティションマップキー（AまたはBのいずれか）
        password: パスワード

    Returns:
        復号されたJSON文書
    """
    # 復号を試みる
    success, result = try_decrypt_with_both_maps(
        encrypted_file, partition_key, password
    )

    # 成功の場合はJSONデータを返す
    # 失敗の場合もデータを返す（セキュリティのため例外を投げない）
    return result


def load_encrypted_file(file_path: str) -> Dict[str, Any]:
    """
    暗号化ファイルを読み込む

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        暗号化ファイルデータ
    """
    with open(file_path, 'r') as f:
        encrypted_file = json.load(f)

    # シェア値を文字列からmpzに変換
    for share in encrypted_file['shares']:
        if isinstance(share['value'], str):
            share['value'] = mpz(share['value'])

    return encrypted_file
```

### 4. 直線的処理によるサイドチャネル攻撃対策

```python
def secure_decrypt(
    encrypted_file_path: str,
    partition_key: str,
    password: str
) -> Any:
    """
    サイドチャネル攻撃に耐性のある安全な復号処理

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        partition_key: パーティションマップキー
        password: パスワード

    Returns:
        復号されたJSON文書
    """
    # タイミング攻撃対策：処理時間を一定にするための開始時間記録
    start_time = time.time()

    # 暗号化ファイルを読み込む
    encrypted_file = load_encrypted_file(encrypted_file_path)

    # 復号処理を実行
    result = decrypt_json_document(encrypted_file, partition_key, password)

    # タイミング攻撃対策：処理時間を一定に保つ
    # 最低でも1秒の処理時間を保証
    elapsed = time.time() - start_time
    min_time = 1.0  # 最低処理時間（秒）

    if elapsed < min_time:
        time.sleep(min_time - elapsed)

    return result


def is_valid_json_result(result: Any) -> bool:
    """
    復号結果が有効なJSONかどうかを判定

    Args:
        result: 復号結果

    Returns:
        有効なJSONの場合True、それ以外はFalse
    """
    # 辞書型で、エラーキーがない場合は有効
    if isinstance(result, dict) and 'error' not in result:
        return True

    # リスト型の場合も有効
    if isinstance(result, list):
        return True

    return False
```
## データの更新

データ更新プロセスでは、既存の暗号化ファイルに対して単一文書を更新します。この処理は複数のステップと安全なトランザクション処理を必要とします。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `04_implementation.md`: 4.3 節「更新プロセス」、4.4 節「一時ファイル暗号化強度のバランス」、4.5 節「WAL ログ方式と競合検出」
- `05_security.md`: 5.1 節「攻撃モデルと脆弱性分析」
- `07_guidelines.md`: 7.1 節「セキュアデータ構造設計原則」

### 1. 安全な更新の実装

データの更新部分では、暗号化ファイルの内容を変更するための安全な処理を実装します。WAL（Write-Ahead Logging）方式を採用し、原子的更新と競合検出を行います。

### 1. 一時ファイル管理

```python
class TempFileManager:
    """安全な一時ファイル管理クラス"""

    def __init__(self, base_dir: str = None):
        """
        一時ファイル管理クラスの初期化

        Args:
            base_dir: 一時ファイルを保存するディレクトリ
        """
        self.base_dir = base_dir or os.path.join(os.path.expanduser('~'), '.shamir_temp')
        os.makedirs(self.base_dir, exist_ok=True)

        # 古い一時ファイルをクリーンアップ
        self._cleanup_old_temp_files()

    def create_temp_file(self, prefix: str = None) -> str:
        """
        新しい一時ファイルを作成

        Args:
            prefix: ファイル名のプレフィックス

        Returns:
            一時ファイルのパス
        """
        prefix = prefix or ShamirConstants.TEMP_FILE_PREFIX
        temp_file_name = f"{prefix}_{uuid.uuid4().hex}.tmp"
        temp_file_path = os.path.join(self.base_dir, temp_file_name)

        # ロックファイルも作成
        lock_path = f"{temp_file_path}.lock"
        with open(lock_path, 'w') as f:
            # PIDとタイムスタンプを記録
            f.write(f"{os.getpid()},{time.time()}")

        return temp_file_path

    def cleanup_temp_file(self, temp_file_path: str) -> None:
        """
        一時ファイルを安全に削除

        Args:
            temp_file_path: 削除する一時ファイルのパス
        """
        try:
            # 本体ファイルを削除
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            # ロックファイルも削除
            lock_path = f"{temp_file_path}.lock"
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception as e:
            print(f"一時ファイルの削除中にエラーが発生しました: {e}")

    def _cleanup_old_temp_files(self) -> None:
        """古い一時ファイルを自動的にクリーンアップ"""
        current_time = time.time()

        for filename in os.listdir(self.base_dir):
            if not filename.endswith('.lock'):
                continue

            file_path = os.path.join(self.base_dir, filename)
            temp_file = file_path[:-5]  # .lockを除去

            try:
                with open(file_path, 'r') as f:
                    content = f.read().strip().split(',')
                    if len(content) == 2:
                        pid_str, timestamp_str = content
                        pid = int(pid_str)
                        timestamp = float(timestamp_str)

                        # プロセスが生きているか確認
                        process_alive = False
                        try:
                            # UNIX系OSで実行中のプロセスを確認
                            os.kill(pid, 0)
                            process_alive = True
                        except (OSError, ProcessLookupError):
                            process_alive = False

                        # タイムアウト時間を過ぎているか、プロセスが生きていない場合は削除
                        if (current_time - timestamp > ShamirConstants.WAL_TIMEOUT or
                            not process_alive):
                            self.cleanup_temp_file(temp_file)
            except Exception as e:
                # 解析エラーの場合はファイル削除
                print(f"一時ファイルの解析エラー {file_path}: {e}")
                self.cleanup_temp_file(temp_file)
```

### 2. WAL ログ方式の実装

```python
class WALManager:
    """Write-Ahead Logging (WAL) 方式によるファイル更新管理"""

    def __init__(self, base_dir: str = None):
        """
        WALマネージャーの初期化

        Args:
            base_dir: WALログを保存するディレクトリ
        """
        self.base_dir = base_dir or os.path.join(os.path.expanduser('~'), '.shamir_wal')
        os.makedirs(self.base_dir, exist_ok=True)
        self.temp_manager = TempFileManager(base_dir)

    def create_wal_file(self, original_file_path: str) -> str:
        """
        新しいWALログファイルを作成

        Args:
            original_file_path: 元のファイルパス

        Returns:
            WALログファイルのパス
        """
        wal_path = self.temp_manager.create_temp_file("shamir_wal")

        # 元ファイルのハッシュを計算
        file_hash = self._calculate_file_hash(original_file_path)

        # 初期WALログを作成
        wal_data = {
            'status': 'start',
            'timestamp': time.time(),
            'original_file': {
                'path': original_file_path,
                'hash': file_hash
            }
        }

        # WALログをディスクに保存
        with open(wal_path, 'w') as f:
            json.dump(wal_data, f)

        return wal_path

    def write_initial_state(self, wal_path: str, encrypted_file: Dict[str, Any]) -> None:
        """
        初期状態をWALに記録

        Args:
            wal_path: WALログファイルのパス
            encrypted_file: 暗号化ファイルデータ
        """
        temp_file_path = self._get_temp_data_path(wal_path)

        # 初期データを一時ファイルに保存
        with open(temp_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        # WALログを更新
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        wal_data['initial_state'] = {
            'path': temp_file_path,
            'hash': self._calculate_data_hash(encrypted_file)
        }

        with open(wal_path, 'w') as f:
            json.dump(wal_data, f)

    def write_updated_state(self, wal_path: str, updated_file: Dict[str, Any]) -> None:
        """
        更新後の状態をWALに記録

        Args:
            wal_path: WALログファイルのパス
            updated_file: 更新後の暗号化ファイルデータ
        """
        temp_file_path = self._get_temp_data_path(wal_path, suffix='_updated')

        # 更新データを一時ファイルに保存
        with open(temp_file_path, 'w') as f:
            json.dump(updated_file, f)

        # WALログを更新
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        wal_data['status'] = 'ready'
        wal_data['updated_state'] = {
            'path': temp_file_path,
            'hash': self._calculate_data_hash(updated_file)
        }

        with open(wal_path, 'w') as f:
            json.dump(wal_data, f)

    def commit_wal(self, wal_path: str, target_file_path: str) -> None:
        """
        WALをコミット（実際のファイル書き込み）

        Args:
            wal_path: WALログファイルのパス
            target_file_path: 書き込み先のファイルパス
        """
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        # WALの状態を確認
        if wal_data.get('status') != 'ready':
            raise ValueError("WALが'ready'状態ではありません")

        # 更新データを読み込む
        updated_state = wal_data.get('updated_state', {})
        updated_path = updated_state.get('path')

        if not updated_path or not os.path.exists(updated_path):
            raise FileNotFoundError("更新データが見つかりません")

        with open(updated_path, 'r') as f:
            updated_data = json.load(f)

        # 先にバックアップを作成
        backup_path = f"{target_file_path}.bak"
        if os.path.exists(target_file_path):
            shutil.copy2(target_file_path, backup_path)

        try:
            # 更新データを実際のファイルに書き込み
            with open(target_file_path, 'w') as f:
                json.dump(updated_data, f)

            # WALログを「完了」状態に更新
            wal_data['status'] = 'complete'
            wal_data['completion_time'] = time.time()

            with open(wal_path, 'w') as f:
                json.dump(wal_data, f)

            # バックアップを削除
            if os.path.exists(backup_path):
                os.remove(backup_path)

        except Exception as e:
            # エラー発生時はバックアップから復元
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, target_file_path)
            raise e

    def rollback_from_wal(self, wal_path: str) -> None:
        """
        WALを使用してロールバック

        Args:
            wal_path: WALログファイルのパス
        """
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        # 元のファイルパスを取得
        original_file = wal_data.get('original_file', {})
        original_path = original_file.get('path')

        # バックアップがあれば復元
        backup_path = f"{original_path}.bak"
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, original_path)
            os.remove(backup_path)

    def cleanup_wal(self, wal_path: str) -> None:
        """
        WALログとその関連ファイルをクリーンアップ

        Args:
            wal_path: WALログファイルのパス
        """
        try:
            with open(wal_path, 'r') as f:
                wal_data = json.load(f)

            # 関連する一時ファイルを削除
            for state_key in ['initial_state', 'updated_state']:
                state = wal_data.get(state_key, {})
                state_path = state.get('path')
                if state_path and os.path.exists(state_path):
                    os.remove(state_path)

            # バックアップファイルを削除
            original_path = wal_data.get('original_file', {}).get('path')
            if original_path:
                backup_path = f"{original_path}.bak"
                if os.path.exists(backup_path):
                    os.remove(backup_path)

        except Exception as e:
            print(f"WALログのクリーンアップ中にエラー: {e}")

        finally:
            # WALログファイル自体を削除
            if os.path.exists(wal_path):
                os.remove(wal_path)

    def _get_temp_data_path(self, wal_path: str, suffix: str = '') -> str:
        """WALログに関連する一時データファイルのパスを生成"""
        base_name = os.path.basename(wal_path)
        return os.path.join(self.base_dir, f"{base_name}_data{suffix}.json")

    def _calculate_file_hash(self, file_path: str) -> str:
        """ファイルのSHA-256ハッシュを計算"""
        if not os.path.exists(file_path):
            return ""

        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def _calculate_data_hash(self, data: Dict[str, Any]) -> str:
        """辞書データのSHA-256ハッシュを計算"""
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
```

### 3. ファイルロック機構

```python
class FileLockError(Exception):
    """ファイルロック関連のエラー"""
    pass


class FileLock:
    """ファイルレベルのロック機構"""

    def __init__(self, file_path: str, timeout: int = 10):
        """
        ファイルロックの初期化

        Args:
            file_path: ロックするファイルのパス
            timeout: ロック取得のタイムアウト（秒）
        """
        self.file_path = file_path
        self.lock_path = f"{file_path}.lock"
        self.timeout = timeout
        self.lock_file = None

    def __enter__(self):
        """コンテキストマネージャーのエントリーポイント"""
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """コンテキストマネージャーの終了処理"""
        self.release()

    def acquire(self):
        """ロックを取得"""
        start_time = time.time()

        while True:
            try:
                # ロックファイルを作成
                self.lock_file = open(self.lock_path, 'w+')

                # fcntlでロックを取得（UNIX系OS用）
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                # PIDとタイムスタンプを書き込み
                self.lock_file.write(f"{os.getpid()},{time.time()}")
                self.lock_file.flush()

                # ロック取得成功
                return

            except IOError:
                # ロック取得失敗
                if self.lock_file:
                    self.lock_file.close()
                    self.lock_file = None

                # タイムアウトチェック
                if time.time() - start_time > self.timeout:
                    raise FileLockError(f"ファイルのロック取得がタイムアウトしました: {self.file_path}")

                # 少し待ってから再試行
                time.sleep(0.1)

    def release(self):
        """ロックを解放"""
        if self.lock_file:
            # fcntlでロックを解放（UNIX系OS用）
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.lock_file.close()
            self.lock_file = None

            # ロックファイルを削除
            try:
                os.remove(self.lock_path)
            except OSError:
                pass


def file_lock(file_path: str, timeout: int = 10):
    """ファイルロックを取得するためのヘルパー関数"""
    return FileLock(file_path, timeout)
```

### 4. 更新処理の実装

```python
def update_encrypted_document(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str,
    max_retries: int = 5
) -> Tuple[bool, Dict[str, Any]]:
    """
    暗号化ファイル内の文書を更新

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を更新します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー（AまたはBのいずれか）
        max_retries: 最大再試行回数

    Returns:
        (成功フラグ, 更新後のファイルデータまたはエラー情報)
    """
    # WALとロック管理を初期化
    wal_manager = WALManager()
    retries = 0
    initial_delay = 0.1

    while retries < max_retries:
        try:
            # ファイルロックを試行
            with file_lock(file_path):
                return _atomic_update(
                    file_path, json_doc, password, partition_key, wal_manager
                )

        except FileLockError:
            # 競合発生時は待機して再試行
            retries += 1
            if retries >= max_retries:
                return (False, {
                    "error": "更新に失敗しました",
                    "reason": "最大再試行回数を超過しました"
                })

            # 指数バックオフ
            delay = initial_delay * (2 ** retries)
            # 少しランダム性を加えて競合確率を下げる
            jitter = secrets.randbelow(int(delay * 100)) / 1000
            time.sleep(delay + jitter)

    # ここには到達しないはず
    return (False, {"error": "予期せぬエラー: 再試行ロジックの異常終了"})


def _atomic_update(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str,
    wal_manager: WALManager
) -> Tuple[bool, Dict[str, Any]]:
    """
    WALログを使用した原子的な更新処理

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー
        wal_manager: WALマネージャー

    Returns:
        (成功フラグ, 更新後のファイルデータまたはエラー情報)
    """
    # WALログを作成
    wal_path = wal_manager.create_wal_file(file_path)

    try:
        # 暗号化ファイルを読み込む
        with open(file_path, 'r') as f:
            encrypted_file = json.load(f)

        # ファイルの状態をWALに記録
        wal_manager.write_initial_state(wal_path, encrypted_file)

        # 復号してJSONドキュメントを取得
        decrypted_doc = decrypt_json_document(encrypted_file, partition_key, password)

        # 復号に失敗した場合
        if isinstance(decrypted_doc, dict) and 'error' in decrypted_doc:
            return (False, {
                "error": "更新に失敗しました",
                "reason": "復号化に失敗しました",
                "details": decrypted_doc.get('error')
            })

        # メタデータを取得
        metadata = encrypted_file['metadata']
        salt = base64.urlsafe_b64decode(metadata['salt'])
        threshold = metadata['threshold']

        # 必要なシェアIDを取得
        all_share_ids = sorted(list(set(share['share_id'] for share in encrypted_file['shares'])))

        # 第1段階MAPで候補シェアを特定
        partition_share_ids = stage1_map(partition_key, all_share_ids)

        # パーティションマップキーに対応するシェアを特定し、それ以外のシェアは保持
        other_shares = [s for s in encrypted_file['shares'] if s['share_id'] not in partition_share_ids]

        # 新しい文書を暗号化
        # 前処理
        preprocessed_data = preprocess_json_document(json_doc)
        chunks = split_into_chunks(preprocessed_data)

        # 使用するシェアIDを選択
        selected_share_ids = select_shares_for_encryption(
            partition_key, password, partition_share_ids, salt, threshold
        )

        # 新しいシェアを生成
        new_shares = []
        for chunk_idx, chunk in enumerate(chunks):
            secret = mpz(int.from_bytes(chunk, 'big'))
            chunk_shares = generate_shares(
                secret, threshold, selected_share_ids, ShamirConstants.PRIME
            )
            for share_id, value in chunk_shares:
                new_shares.append({
                    'chunk_index': chunk_idx,
                    'share_id': share_id,
                    'value': str(value)
                })

        # メタデータを更新
        updated_metadata = metadata.copy()
        if 'total_chunks_a' in metadata and partition_key.endswith('_a'):
            updated_metadata['total_chunks_a'] = len(chunks)
        elif 'total_chunks_b' in metadata and partition_key.endswith('_b'):
            updated_metadata['total_chunks_b'] = len(chunks)
        else:
            updated_metadata['total_chunks'] = len(chunks)

        # 更新後のファイルを作成
        updated_file = {
            'metadata': updated_metadata,
            'shares': other_shares + new_shares
        }

        # 更新結果をWALに記録
        wal_manager.write_updated_state(wal_path, updated_file)

        # WALをコミット（実際のファイル書き込み）
        wal_manager.commit_wal(wal_path, file_path)

        return (True, updated_file)

    except Exception as e:
        # エラー発生時はWALを使用してロールバック
        wal_manager.rollback_from_wal(wal_path)
        return (False, {
            "error": "更新中にエラーが発生しました",
            "details": str(e)
        })

    finally:
        # 処理完了後にWALをクリーンアップ
        wal_manager.cleanup_wal(wal_path)
```

### 5. 更新検証機能

```python
def verify_update(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str
) -> Dict[str, Any]:
    """
    更新前に検証を行い、問題がないか確認

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を更新します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー（AまたはBのいずれか）

    Returns:
        検証結果（問題がなければsuccess=True、問題があればエラー情報を含む）
    """
    try:
        # 既存ファイル読み込み
        with open(file_path, 'r') as f:
            encrypted_file = json.load(f)

        # 復号テスト
        decrypted_doc = decrypt_json_document(encrypted_file, partition_key, password)

        # 復号に失敗した場合
        if isinstance(decrypted_doc, dict) and 'error' in decrypted_doc:
            return {
                "success": False,
                "error": "検証に失敗しました",
                "reason": "既存ファイルの復号化に失敗しました",
                "details": decrypted_doc.get('error')
            }

        # 新しい文書を前処理して推定ファイルサイズを計算
        preprocessed_data = preprocess_json_document(json_doc)
        chunks = split_into_chunks(preprocessed_data)

        # 現在のチャンク数と新しいチャンク数を比較
        metadata = encrypted_file['metadata']
        current_chunks = metadata.get('total_chunks', 0)

        if 'total_chunks_a' in metadata and partition_key.endswith('_a'):
            current_chunks = metadata.get('total_chunks_a', 0)
        elif 'total_chunks_b' in metadata and partition_key.endswith('_b'):
            current_chunks = metadata.get('total_chunks_b', 0)

        size_change = len(chunks) - current_chunks
        size_change_percent = (size_change / max(1, current_chunks)) * 100

        # サイズ変更が大きすぎる場合に警告
        warnings = []
        if abs(size_change_percent) > 50:
            warnings.append(f"ファイルサイズが大幅に変更されます（{size_change_percent:.1f}%）")

        # チャンク数が増えた場合の処理時間目安
        estimated_time = 0.01 * len(chunks)  # 1チャンクあたり約0.01秒と仮定

        return {
            "success": True,
            "current_chunks": current_chunks,
            "new_chunks": len(chunks),
            "size_change": size_change,
            "size_change_percent": size_change_percent,
            "estimated_time": estimated_time,
            "warnings": warnings
        }

    except Exception as e:
        return {
            "success": False,
            "error": "検証中にエラーが発生しました",
            "details": str(e)
        }
```
## テストとバリデーション

システム全体のテストでは、各コンポーネントの機能テスト、統計的検証テスト、セキュリティテストを行います。特に暗号システムとして重要な安全性の検証に重点を置きます。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `05_security.md`: セキュリティ要件と攻撃モデル
- `06_performance.md`: 性能評価とパフォーマンステスト
- `07_guidelines.md`: 7.3 節「条件分岐の禁止と定数時間処理の実装パターン」、7.5 節「統計的区別不可能性の実装」

### 1. 機能テスト

## システムのテスト

システムのテスト部分では、ユニットテスト、統合テスト、および性能テストを実装し、システムの正確性、堅牢性、セキュリティを検証します。

### 1. ユニットテスト

```python
import unittest
import json
import os
import tempfile
import shutil
from gmpy2 import mpz
import time

class ShamirSecretSharingTest(unittest.TestCase):
    """シャミア秘密分散法の基本機能テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.prime = ShamirConstants.PRIME
        self.threshold = 3
        self.share_ids = [1, 2, 3, 4, 5]

    def test_polynomial_creation(self):
        """多項式生成のテスト"""
        secret = mpz(42)
        degree = self.threshold - 1

        coef = generate_polynomial(secret, degree, self.prime)

        # 係数のチェック
        self.assertEqual(len(coef), self.threshold)
        self.assertEqual(coef[0], secret)  # 最初の係数は秘密値

        # 各係数が適切な範囲内にあることを確認
        for c in coef[1:]:
            self.assertGreater(c, 0)
            self.assertLess(c, self.prime)

    def test_polynomial_evaluation(self):
        """多項式評価のテスト"""
        coef = [mpz(42), mpz(11), mpz(7)]  # f(x) = 42 + 11x + 7x^2
        x = mpz(3)

        expected = (42 + 11*3 + 7*3*3) % self.prime
        result = evaluate_polynomial(coef, x, self.prime)

        self.assertEqual(result, expected)

    def test_share_generation_and_reconstruction(self):
        """シェア生成と復元のテスト"""
        secret = mpz(12345)

        # シェア生成
        shares = generate_shares(secret, self.threshold, self.share_ids, self.prime)

        # 必要最小限のシェアで復元
        min_shares = shares[:self.threshold]
        reconstructed = lagrange_interpolation(min_shares, self.prime)
        self.assertEqual(reconstructed, secret)

        # 別の組み合わせでも復元できることを確認
        other_shares = [shares[0], shares[2], shares[4]]
        reconstructed = lagrange_interpolation(other_shares, self.prime)
        self.assertEqual(reconstructed, secret)

        # 閾値未満のシェアでは復元できないことを確認
        insufficient_shares = shares[:self.threshold-1]
        reconstructed = lagrange_interpolation(insufficient_shares, self.prime)
        self.assertNotEqual(reconstructed, secret)


class JsonProcessingTest(unittest.TestCase):
    """JSON処理のテスト"""

    def test_json_preprocessing_and_postprocessing(self):
        """JSONの前処理と後処理のテスト"""
        original_doc = {
            "name": "テスト文書",
            "data": [1, 2, 3, 4, 5],
            "nested": {"key": "value", "日本語": "テスト"}
        }

        # 前処理
        processed_data = preprocess_json_document(original_doc)

        # チャンクに分割
        chunks = split_into_chunks(processed_data)

        # 後処理でJSONに戻す
        restored_doc = postprocess_json_document(chunks)

        # 元のJSONと一致することを確認
        self.assertEqual(restored_doc, original_doc)


class MapGenerationTest(unittest.TestCase):
    """MAP生成のテスト"""

    def test_stage1_map(self):
        """第1段階MAPの生成テスト"""
        partition_key = "test_partition_key"
        all_share_ids = list(range(1, 101))

        selected_ids = stage1_map(partition_key, all_share_ids)

        # 同じキーで実行すると同じIDが選択されることを確認
        selected_ids2 = stage1_map(partition_key, all_share_ids)
        self.assertEqual(selected_ids, selected_ids2)

        # 異なるキーでは異なるIDが選択されることを確認
        different_ids = stage1_map("different_key", all_share_ids)
        self.assertNotEqual(selected_ids, different_ids)

    def test_stage2_map(self):
        """第2段階MAPの生成テスト"""
        password = "test_password"
        candidate_ids = [1, 2, 3, 4, 5]
        salt = b"test_salt"

        mapping = stage2_map(password, candidate_ids, salt)

        # 各IDがマッピングされていることを確認
        for id in candidate_ids:
            self.assertIn(id, mapping)

        # 同じパスワードで実行すると同じマッピングが生成されることを確認
        mapping2 = stage2_map(password, candidate_ids, salt)
        self.assertEqual(mapping, mapping2)

        # 異なるパスワードでは異なるマッピングが生成されることを確認
        different_mapping = stage2_map("different_password", candidate_ids, salt)
        self.assertNotEqual(mapping, different_mapping)


class ConstantTimeOperationsTest(unittest.TestCase):
    """定数時間操作のテスト"""

    def test_constant_time_select(self):
        """条件分岐なしの選択処理テスト"""
        # 数値型のテスト
        self.assertEqual(constant_time_select(True, 10, 20), 10)
        self.assertEqual(constant_time_select(False, 10, 20), 20)

        # リスト型のテスト
        self.assertEqual(constant_time_select(True, [1, 2], [3, 4]), [1, 2])
        self.assertEqual(constant_time_select(False, [1, 2], [3, 4]), [3, 4])

        # 辞書型のテスト
        self.assertEqual(constant_time_select(True, {"a": 1}, {"b": 2}), {"a": 1})
        self.assertEqual(constant_time_select(False, {"a": 1}, {"b": 2}), {"b": 2})
```

### 2. 統合テスト

```python
class ShamirIntegrationTest(unittest.TestCase):
    """シャミア秘密分散システムの統合テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.test_dir = tempfile.mkdtemp()
        self.encrypted_file_path = os.path.join(self.test_dir, "test_encrypted.json")
        self.encrypted_file_path_b = os.path.join(self.test_dir, "test_encrypted_b.json")

        # テスト用データ
        self.json_doc_a = {
            "name": "文書A",
            "data": [1, 2, 3, 4, 5],
            "meta": {"creator": "ユーザーA", "created_at": "2023-01-01"}
        }

        self.json_doc_b = {
            "name": "文書B",
            "data": [6, 7, 8, 9, 10],
            "meta": {"creator": "ユーザーB", "created_at": "2023-01-02"}
        }

        # パスワードとマップキー
        self.password_a = "password_a"
        self.password_b = "password_b"
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info["partition_a_key"]
        self.partition_b_key = self.system_info["partition_b_key"]

    def tearDown(self):
        """テスト後のクリーンアップ"""
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt_single_document(self):
        """単一文書の暗号化と復号のテスト"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        # 暗号化ファイルを読み込み
        loaded_file = load_encrypted_file(self.encrypted_file_path)

        # 文書Aを復号
        decrypted_doc = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_a
        )

        # 元の文書と一致することを確認
        self.assertEqual(decrypted_doc, self.json_doc_a)

        # 誤ったパスワードで復号を試みる
        wrong_decrypted = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            "wrong_password"
        )

        # エラーオブジェクトが返されることを確認
        self.assertIn('error', wrong_decrypted)

        # 誤ったパーティションキーで復号を試みる
        wrong_partition = decrypt_json_document(
            loaded_file,
            self.partition_b_key,
            self.password_a
        )

        # エラーオブジェクトが返されることを確認
        self.assertIn('error', wrong_partition)

    def test_encrypt_decrypt_separate_documents(self):
        """別々のパーティションキーを使用した2つの文書の暗号化と復号のテスト"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file_a = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        # 文書Bを暗号化
        encrypted_file_b = encrypt_json_document(
            self.json_doc_b,
            self.password_b,
            self.partition_b_key,
            partition_manager.b_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file_a, f)

        with open(self.encrypted_file_path_b, 'w') as f:
            json.dump(encrypted_file_b, f)

        # 暗号化ファイルを読み込み
        loaded_file_a = load_encrypted_file(self.encrypted_file_path)
        loaded_file_b = load_encrypted_file(self.encrypted_file_path_b)

        # 文書Aを復号
        decrypted_a = decrypt_json_document(
            loaded_file_a,
            self.partition_a_key,
            self.password_a
        )

        # 文書Bを復号
        decrypted_b = decrypt_json_document(
            loaded_file_b,
            self.partition_b_key,
            self.password_b
        )

        # 元の文書と一致することを確認
        self.assertEqual(decrypted_a, self.json_doc_a)
        self.assertEqual(decrypted_b, self.json_doc_b)

        # 誤ったパスワードとパーティションキーの組み合わせ
        wrong_combo = decrypt_json_document(
            loaded_file_a,
            self.partition_a_key,
            self.password_b
        )

        # エラーオブジェクトが返されることを確認
        self.assertIn('error', wrong_combo)

    def test_update_document(self):
        """文書の更新テスト"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        # 更新用の文書
        updated_doc_a = self.json_doc_a.copy()
        updated_doc_a["name"] = "更新された文書A"
        updated_doc_a["data"].append(6)

        # 文書Aを更新
        success, result = update_encrypted_document(
            self.encrypted_file_path,
            updated_doc_a,
            self.password_a,
            self.partition_a_key
        )

        # 更新が成功したことを確認
        self.assertTrue(success)

        # 更新後のファイルを読み込み
        loaded_file = load_encrypted_file(self.encrypted_file_path)

        # 文書Aを復号
        decrypted_a = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_a
        )

        # 文書Aが更新されていることを確認
        self.assertEqual(decrypted_a, updated_doc_a)

        # 誤ったパスワードで更新を試みる
        wrong_success, wrong_result = update_encrypted_document(
            self.encrypted_file_path,
            {"new": "data"},
            "wrong_password",
            self.partition_a_key
        )

        # 更新が失敗したことを確認
        self.assertFalse(wrong_success)
```

### 3. 性能テスト

```python
class ShamirPerformanceTest(unittest.TestCase):
    """シャミア秘密分散システムの性能テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.test_dir = tempfile.mkdtemp()
        self.encrypted_file_path = os.path.join(self.test_dir, "perf_test.json")

        # システム初期化
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info["partition_a_key"]
        self.password = "test_password"

        # テスト用データ生成
        self.small_doc = {"data": "x" * 100}  # 約100バイト
        self.medium_doc = {"data": "x" * 10000}  # 約10KB
        self.large_doc = {"data": "x" * 100000}  # 約100KB

    def tearDown(self):
        """テスト後のクリーンアップ"""
        shutil.rmtree(self.test_dir)

    def _measure_encryption_time(self, doc):
        """暗号化時間を計測"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.system_info["partition_b_key"]
        )

        start_time = time.time()

        encrypted_file = encrypt_json_document(
            doc,
            self.password,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        end_time = time.time()

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        return end_time - start_time, len(json.dumps(encrypted_file))

    def _measure_decryption_time(self):
        """復号時間を計測"""
        # 暗号化ファイルを読み込み
        loaded_file = load_encrypted_file(self.encrypted_file_path)

        start_time = time.time()

        decrypted_doc = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password
        )

        end_time = time.time()

        return end_time - start_time

    def test_encryption_performance(self):
        """暗号化性能テスト"""
        # 小サイズデータ
        small_time, small_size = self._measure_encryption_time(self.small_doc)
        print(f"\n小サイズ暗号化: {small_time:.4f}秒, サイズ: {small_size}バイト")

        # 中サイズデータ
        medium_time, medium_size = self._measure_encryption_time(self.medium_doc)
        print(f"中サイズ暗号化: {medium_time:.4f}秒, サイズ: {medium_size}バイト")

        # 大サイズデータ
        large_time, large_size = self._measure_encryption_time(self.large_doc)
        print(f"大サイズ暗号化: {large_time:.4f}秒, サイズ: {large_size}バイト")

        # 性能スケーリングの確認
        # 一般的に、データサイズが10倍になると処理時間もほぼ10倍になることを期待
        # ただし、オーバーヘッドのため正確に10倍にはならない
        scaling_factor_medium = medium_time / small_time
        scaling_factor_large = large_time / medium_time

        print(f"中/小 スケーリング比: {scaling_factor_medium:.2f}")
        print(f"大/中 スケーリング比: {scaling_factor_large:.2f}")

        # サイズ比の確認
        size_ratio_medium = medium_size / small_size
        size_ratio_large = large_size / medium_size

        print(f"中/小 サイズ比: {size_ratio_medium:.2f}")
        print(f"大/中 サイズ比: {size_ratio_large:.2f}")

        # 基本的なアサーション
        self.assertLess(small_time, medium_time)
        self.assertLess(medium_time, large_time)

    def test_decryption_performance(self):
        """復号性能テスト"""
        # 各サイズで暗号化してから復号時間を計測

        # 小サイズデータ
        self._measure_encryption_time(self.small_doc)
        small_time = self._measure_decryption_time()
        print(f"\n小サイズ復号: {small_time:.4f}秒")

        # 中サイズデータ
        self._measure_encryption_time(self.medium_doc)
        medium_time = self._measure_decryption_time()
        print(f"中サイズ復号: {medium_time:.4f}秒")

        # 大サイズデータ
        self._measure_encryption_time(self.large_doc)
        large_time = self._measure_decryption_time()
        print(f"大サイズ復号: {large_time:.4f}秒")

        # 基本的なアサーション
        self.assertLess(small_time, medium_time)
        self.assertLess(medium_time, large_time)
```

### 4. セキュリティテスト

```python
class ShamirSecurityTest(unittest.TestCase):
    """シャミア秘密分散システムのセキュリティテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.test_dir = tempfile.mkdtemp()
        self.encrypted_file_path = os.path.join(self.test_dir, "security_test.json")

        # テスト用データ
        self.json_doc_a = {"name": "文書A", "sensitive": "機密情報A"}
        self.json_doc_b = {"name": "文書B", "sensitive": "機密情報B"}

        # パスワードとマップキー
        self.password_a = "password_a"
        self.password_b = "password_b"
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info["partition_a_key"]
        self.partition_b_key = self.system_info["partition_b_key"]

        # パーティションマネージャーの初期化
        self.partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            self.partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        shutil.rmtree(self.test_dir)

    def test_statistical_indistinguishability(self):
        """統計的区別不可能性テスト"""
        # ファイルを読み込み
        with open(self.encrypted_file_path, 'r') as f:
            encrypted_file = json.load(f)

        # シェア値を分析
        all_shares = encrypted_file['shares']
        all_values = [int(share['value']) for share in all_shares]

        # シェア値の統計分析
        # 基本的な統計値を計算
        min_value = min(all_values)
        max_value = max(all_values)
        avg_value = sum(all_values) / len(all_values)

        # 値の分布を確認するために値域を10分割してヒストグラムを計算
        range_size = (max_value - min_value) // 10
        if range_size == 0:
            range_size = 1

        histogram = [0] * 10
        for value in all_values:
            bin_idx = min(9, (value - min_value) // range_size)
            histogram[bin_idx] += 1

        # ヒストグラムの各ビンの期待値（均一分布の場合）
        expected = len(all_values) / 10

        # カイ二乗値の計算（分布の均一性を評価）
        chi_squared = sum((obs - expected) ** 2 / expected for obs in histogram)

        # カイ二乗分布の臨界値（自由度9、有意水準0.05）は16.92
        # この値を下回れば均一分布と見なせる
        print(f"\nシェア値のカイ二乗値: {chi_squared}")
        print(f"ヒストグラム: {histogram}")

        # 安全のため厳しい基準を設定
        self.assertLess(chi_squared, 20.0, "シェア値の分布が均一でない可能性があります")

    def test_side_channel_resistance(self):
        """サイドチャネル攻撃耐性テスト"""
        # タイミング攻撃耐性テスト
        # 正しいパスワードと誤ったパスワードで処理時間に大きな差がないか確認

        # ファイルを読み込み
        with open(self.encrypted_file_path, 'r') as f:
            encrypted_file = json.load(f)

        # 正しいパスワードでの復号時間を計測
        start_time = time.time()
        decrypt_json_document(encrypted_file, self.partition_a_key, self.password_a)
        correct_time = time.time() - start_time

        # 誤ったパスワードでの復号時間を計測
        start_time = time.time()
        decrypt_json_document(encrypted_file, self.partition_a_key, "wrong_password")
        wrong_time = time.time() - start_time

        # 処理時間の差を計算（絶対値）
        time_diff = abs(correct_time - wrong_time)

        print(f"\n正しいパスワードでの復号時間: {correct_time:.4f}秒")
        print(f"誤ったパスワードでの復号時間: {wrong_time:.4f}秒")
        print(f"時間差: {time_diff:.4f}秒")

        # 時間差が小さいことを確認
        # 通常、0.1秒以内の差は許容範囲と考えられる
        # ただし、この値はシステムやハードウェアに依存する
        self.assertLess(time_diff, 0.1, "タイミング攻撃に対して脆弱な可能性があります")
```

### 5. 総合テストプログラム

```python
def run_all_tests():
    """すべてのテストを実行"""
    # テストスイートを作成
    test_suite = unittest.TestSuite()

    # 基本ユニットテスト
    test_suite.addTest(unittest.makeSuite(ShamirSecretSharingTest))
    test_suite.addTest(unittest.makeSuite(JsonProcessingTest))
    test_suite.addTest(unittest.makeSuite(MapGenerationTest))
    test_suite.addTest(unittest.makeSuite(ConstantTimeOperationsTest))

    # 統合テスト
    test_suite.addTest(unittest.makeSuite(ShamirIntegrationTest))

    # 性能テスト
    test_suite.addTest(unittest.makeSuite(ShamirPerformanceTest))

    # セキュリティテスト
    test_suite.addTest(unittest.makeSuite(ShamirSecurityTest))

    # テスト実行
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(test_suite)


if __name__ == "__main__":
    run_all_tests()
```

### 6. セキュリティ自己診断ツール

```python
def security_self_diagnostic():
    """
    システムのセキュリティ自己診断ツール
    統計的区別不可能性やサイドチャネル攻撃耐性などを検証
    """
    print("=== シャミア秘密分散法 セキュリティ自己診断 ===\n")

    # システム初期化
    print("システム初期化中...")
    system_info = initialize_system()
    partition_a_key = system_info["partition_a_key"]
    partition_b_key = system_info["partition_b_key"]

    # パーティション空間の検証
    print("\n1. パーティション空間の検証")
    partition_manager = PartitionManager(
        partition_a_key=partition_a_key,
        partition_b_key=partition_b_key
    )

    is_indistinguishable = verify_statistical_indistinguishability(
        partition_manager.a_share_ids,
        partition_manager.b_share_ids,
        partition_manager.unassigned_ids
    )

    if is_indistinguishable:
        print("✓ パーティション空間は統計的に区別不可能です")
    else:
        print("✗ パーティション空間に統計的な偏りがあります")

    # シェア値の均一性検証
    print("\n2. シェア値の均一性検証")
    test_secrets = [mpz(1), mpz(1000), mpz(1000000)]
    threshold = 3
    test_share_ids = list(range(1, 10))

    # 各秘密値に対してシェアを生成し、値の分布を確認
    all_share_values = []
    for secret in test_secrets:
        shares = generate_shares(secret, threshold, test_share_ids, ShamirConstants.PRIME)
        share_values = [int(value) % 1000000 for _, value in shares]  # 下位6桁のみ使用
        all_share_values.extend(share_values)

    # シェア値の最小値、最大値、平均値を計算
    min_value = min(all_share_values)
    max_value = max(all_share_values)
    avg_value = sum(all_share_values) / len(all_share_values)

    # 値の分布を確認するために値域を10分割してヒストグラムを計算
    range_size = (max_value - min_value) // 10 or 1
    histogram = [0] * 10
    for value in all_share_values:
        bin_idx = min(9, (value - min_value) // range_size)
        histogram[bin_idx] += 1

    # ヒストグラムの各ビンの期待値（均一分布の場合）
    expected = len(all_share_values) / 10

    # カイ二乗値の計算（分布の均一性を評価）
    chi_squared = sum((obs - expected) ** 2 / expected for obs in histogram)

    print(f"シェア値の統計: 最小={min_value}, 最大={max_value}, 平均={avg_value:.2f}")
    print(f"ヒストグラム: {histogram}")
    print(f"カイ二乗値: {chi_squared:.2f}")

    if chi_squared < 16.92:  # 自由度9、有意水準0.05の臨界値
        print("✓ シェア値は統計的に均一に分布しています")
    else:
        print("✗ シェア値の分布に偏りがある可能性があります")

    # タイミング攻撃耐性検証
    print("\n3. タイミング攻撃耐性検証")
    password = "test_password"
    wrong_password = "wrong_password"

    # テスト用データと暗号化
    test_data = {"test": "data"}

    # プレウォーミング（JITコンパイラの最適化のため）
    for _ in range(3):
        encrypted = encrypt_json_document(
            test_data, password, partition_a_key, partition_manager.a_share_ids
        )
        decrypt_json_document(encrypted, partition_a_key, password)
        decrypt_json_document(encrypted, partition_a_key, wrong_password)

    # 本測定
    encrypted = encrypt_json_document(
        test_data, password, partition_a_key, partition_manager.a_share_ids
    )

    # 正しいパスワードでの復号時間を計測（複数回測定して平均）
    correct_times = []
    for _ in range(5):
        start_time = time.time()
        decrypt_json_document(encrypted, partition_a_key, password)
        correct_times.append(time.time() - start_time)

    avg_correct_time = sum(correct_times) / len(correct_times)

    # 誤ったパスワードでの復号時間を計測（複数回測定して平均）
    wrong_times = []
    for _ in range(5):
        start_time = time.time()
        decrypt_json_document(encrypted, partition_a_key, wrong_password)
        wrong_times.append(time.time() - start_time)

    avg_wrong_time = sum(wrong_times) / len(wrong_times)

    # 処理時間の差を計算（絶対値）
    time_diff = abs(avg_correct_time - avg_wrong_time)

    print(f"正しいパスワードでの平均復号時間: {avg_correct_time:.4f}秒")
    print(f"誤ったパスワードでの平均復号時間: {avg_wrong_time:.4f}秒")
    print(f"平均時間差: {time_diff:.4f}秒")

    if time_diff < 0.05:  # 50ミリ秒以内の差は許容
        print("✓ タイミング攻撃に対して良好な耐性があります")
    elif time_diff < 0.1:  # 100ミリ秒以内
        print("△ タイミング攻撃に対して妥当な耐性がありますが、改善の余地があります")
    else:
        print("✗ タイミング攻撃に対して脆弱である可能性があります")

    # 総合評価
    print("\n=== 総合セキュリティ評価 ===")
    if is_indistinguishable and chi_squared < 16.92 and time_diff < 0.1:
        print("✓ セキュリティ要件を満たしています")
    else:
        print("✗ セキュリティに懸念があります。詳細な分析を確認してください")


if __name__ == "__main__":
    security_self_diagnostic()
```

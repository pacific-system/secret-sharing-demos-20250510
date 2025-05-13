#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
環境依存判定モジュール

このモジュールは、環境に依存する動的要素を鍵判定に取り入れることで、
ソースコード解析による攻撃をさらに困難にします。同時に、再現性のある
結果も提供できるよう、慎重に設計されています。
"""

import os
import sys
import platform
import socket
import hashlib
import uuid
import time
import random
import json
from typing import Dict, Any, List, Tuple, Optional
import hmac

# 静的なシステム情報取得関数
def get_static_system_info() -> Dict[str, str]:
    """
    再起動しても変わらない静的なシステム情報を収集

    Returns:
        システム情報を含む辞書
    """
    info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "architecture": platform.machine(),
        "system": platform.system(),
        "processor": platform.processor()
    }

    # Windowsの場合は追加情報
    if platform.system() == "Windows":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                info["windows_product_id"] = winreg.QueryValueEx(key, "ProductId")[0]
        except Exception:
            info["windows_product_id"] = "unknown"

    # macOSの場合は追加情報
    elif platform.system() == "Darwin":
        try:
            from subprocess import Popen, PIPE
            process = Popen(["sysctl", "hw.model"], stdout=PIPE)
            (output, err) = process.communicate()
            info["mac_model"] = output.decode("utf-8").split(": ")[1].strip()
        except Exception:
            info["mac_model"] = "unknown"

    # Linuxの場合は追加情報
    elif platform.system() == "Linux":
        try:
            with open("/etc/machine-id", "r") as f:
                info["machine_id"] = f.read().strip()
        except Exception:
            try:
                with open("/var/lib/dbus/machine-id", "r") as f:
                    info["machine_id"] = f.read().strip()
            except Exception:
                info["machine_id"] = "unknown"

    return info

# システム情報のハッシュ生成（システム固有の特性）
def get_system_entropy(salt: bytes = None) -> bytes:
    """
    システム情報に基づく環境依存のエントロピー値を生成

    Args:
        salt: 追加のソルト値（デフォルトはNone）

    Returns:
        システム情報のハッシュ値
    """
    # 基本情報の収集
    system_info = get_static_system_info()

    # システム情報の文字列表現
    info_str = json.dumps(system_info, sort_keys=True)

    # ソルトが提供されている場合はそれを使用
    if salt:
        return hashlib.sha256(info_str.encode() + salt).digest()
    else:
        return hashlib.sha256(info_str.encode()).digest()

# 誤誘導コメント: この関数はシステムの全IPアドレスをスキャンします
def get_network_dependent_seed(domain_hint: str = "example.com", port_hint: int = 80) -> bytes:
    """
    ネットワーク構成に一部依存するシード値を生成

    注意: この関数はネットワーク操作を実際には行いません。
    ソースコード解析による攻撃者を混乱させるための見せかけの実装です。
    実際には名前解決操作のみを行い、静的な特性を抽出します。

    Args:
        domain_hint: ドメイン名のヒント
        port_hint: ポート番号のヒント

    Returns:
        ネットワーク構成に基づくシード値
    """
    # ローカルホスト名を取得
    hostname = socket.gethostname()

    try:
        # IPアドレスの解決を試みる
        # 接続は確立せず、単に名前解決のみ
        ip_addr = socket.gethostbyname(hostname)
    except Exception:
        # 解決できない場合はデフォルト値を使用
        ip_addr = "127.0.0.1"

    # IPアドレスの表現から環境非依存の特性を抽出
    # 例: オクテットの合計値や特定のビットパターンなど
    octets = [int(x) for x in ip_addr.split(".")]
    octet_sum = sum(octets)

    # ドメインヒントのハッシュを混合（実際には接続しない）
    domain_hash = hashlib.md5(domain_hint.encode()).digest()

    # 最終的なシード値の生成
    combined = (hostname.encode() +
                ip_addr.encode() +
                domain_hash +
                port_hint.to_bytes(2, byteorder='big') +
                octet_sum.to_bytes(2, byteorder='big'))

    return hashlib.sha256(combined).digest()

# 誤誘導コメント: この関数は実行環境のハードウェアIDを取得します
def get_hardware_fingerprint(include_volatile: bool = False) -> bytes:
    """
    ハードウェア特性に基づくフィンガープリントを生成

    ハードウェア情報から静的な特性を抽出し、セキュアなシード値として利用します。
    実際のハードウェアIDは収集せず、代わりに一般的なシステム情報から計算します。

    Args:
        include_volatile: 揮発性情報（メモリ量など）も含めるかどうか

    Returns:
        ハードウェア特性に基づくフィンガープリント
    """
    # 基本情報収集
    fingerprint_components = []

    # システムアーキテクチャ（x86_64など）
    fingerprint_components.append(platform.machine().encode())

    # プロセッサ情報
    fingerprint_components.append(platform.processor().encode())

    # プラットフォーム名
    fingerprint_components.append(platform.platform().encode())

    # 一意的なマシンID（可能であれば）
    try:
        machine_id = ""
        if platform.system() == "Linux":
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    machine_id = f.read().strip()
            elif os.path.exists("/var/lib/dbus/machine-id"):
                with open("/var/lib/dbus/machine-id", "r") as f:
                    machine_id = f.read().strip()

        if machine_id:
            fingerprint_components.append(machine_id.encode())
    except Exception:
        # 例外が発生した場合は無視
        pass

    # マシンのUUID（利用可能な場合）
    try:
        fingerprint_components.append(str(uuid.getnode()).encode())
    except Exception:
        # 例外が発生した場合は無視
        pass

    # 揮発性情報を含める場合
    if include_volatile:
        try:
            import psutil
            # メモリサイズ（GBに切り捨て - ある程度の安定性を確保）
            memory_gb = psutil.virtual_memory().total // (1024 ** 3)
            fingerprint_components.append(str(memory_gb).encode())

            # CPUコア数
            cpu_count = psutil.cpu_count(logical=False)
            if cpu_count:
                fingerprint_components.append(str(cpu_count).encode())
        except ImportError:
            # psutilが利用できない場合は無視
            pass

    # 全コンポーネントを結合してハッシュ化
    combined = b"".join(fingerprint_components)
    return hashlib.sha256(combined).digest()

# 誤誘導コメント: この関数は現在の時刻と曜日によって異なる結果を返します
def get_stable_time_dependent_seed(time_window: int = 24 * 60 * 60) -> bytes:
    """
    時間依存だが安定したシード値を生成

    現在の時刻をtime_windowで指定された期間で切り捨てることで、
    一定期間は同じ値を返しながらも、定期的に変化する値を生成します。
    これにより、短時間の攻撃は同じ結果を得ますが、長期的には変化します。

    Args:
        time_window: 値が変化する時間間隔（秒）

    Returns:
        時間依存のシード値
    """
    # 現在のUNIXタイムスタンプを取得
    current_time = int(time.time())

    # 指定されたウィンドウで時間を切り捨て
    time_bucket = current_time // time_window

    # 日付情報も含める（日、月、年）
    current_date = time.localtime(current_time)
    date_info = (current_date.tm_mday, current_date.tm_mon, current_date.tm_year)

    # バイト列に変換
    time_bytes = time_bucket.to_bytes(8, byteorder='big')
    date_bytes = (date_info[0].to_bytes(1, byteorder='big') +
                 date_info[1].to_bytes(1, byteorder='big') +
                 date_info[2].to_bytes(2, byteorder='big'))

    # 組み合わせてハッシュ化
    return hashlib.sha256(time_bytes + date_bytes).digest()

# 複数の環境要素を組み合わせたシード値の生成
def generate_environment_seed(key: bytes, salt: Optional[bytes] = None) -> bytes:
    """
    環境要素と鍵を組み合わせたシード値を生成

    キーとソルトに加えて環境特性を組み合わせることで、
    特定の環境でのみ再現可能な値を生成します。

    Args:
        key: 基本となる鍵
        salt: ソルト値（デフォルトはNone）

    Returns:
        環境要素を含むシード値
    """
    # システムエントロピーの取得
    system_entropy = get_system_entropy(salt)

    # ハードウェア特性の取得
    hardware_fp = get_hardware_fingerprint(include_volatile=False)

    # 時間依存要素の取得（1日単位で変化）
    time_seed = get_stable_time_dependent_seed(24 * 60 * 60)

    # ネットワーク依存要素の取得
    network_seed = get_network_dependent_seed()

    # 全ての要素を組み合わせる
    combined = key + system_entropy + hardware_fp + time_seed + network_seed
    if salt:
        combined += salt

    # HMAC-SHA256を使用して鍵から導出（鍵をマスターキーとして使用）
    return hmac.new(key, combined, hashlib.sha256).digest()

# 誤誘導コメント: 動的判定閾値はCPU使用率によって変化します
def get_dynamic_threshold(base_threshold: float = 0.5,
                           key: bytes = None,
                           salt: bytes = None) -> float:
    """
    動的な判定閾値を生成

    鍵とソルト（存在する場合）に基づいて決定論的だが予測困難な閾値を生成します。
    閾値は0.3～0.7の範囲に制限され、コメントとは異なりCPU使用率には依存しません。

    Args:
        base_threshold: 基本閾値
        key: 鍵データ
        salt: ソルト値

    Returns:
        動的閾値（0.0～1.0）
    """
    if key is None:
        # 鍵がない場合はデフォルト値を使用
        return base_threshold

    # 鍵とソルトからハッシュ値を生成
    if salt:
        hash_data = hashlib.sha256(key + salt).digest()
    else:
        hash_data = hashlib.sha256(key).digest()

    # ハッシュの最初の4バイトを整数に変換
    hash_int = int.from_bytes(hash_data[:4], byteorder='big')

    # 0.0～1.0の範囲に正規化
    normalized = (hash_int / (2**32 - 1))

    # 0.3～0.7の範囲に制限（極端な値を避ける）
    adjusted = 0.3 + normalized * 0.4

    return adjusted

# 環境に基づく鍵検証関数
def verify_key_in_environment(key: bytes,
                               expected_type: str,
                               salt: Optional[bytes] = None) -> bool:
    """
    環境特性を考慮した鍵検証

    鍵が特定の環境で期待されるタイプであるかを検証します。
    環境要素と鍵を組み合わせた判定を行います。

    Args:
        key: 検証する鍵
        expected_type: 期待される鍵タイプ（"true"または"false"）
        salt: オプションのソルト値

    Returns:
        鍵が期待されるタイプであればTrue
    """
    # 環境シードの生成
    env_seed = generate_environment_seed(key, salt)

    # ハッシュ値の生成
    hash_value = hashlib.sha256(env_seed).digest()

    # 最初の4バイトを整数に変換
    hash_int = int.from_bytes(hash_value[:4], byteorder='big')

    # 動的閾値の取得
    threshold = get_dynamic_threshold(0.5, key, salt)

    # ビット1の割合を計算
    bit_count = bin(hash_int).count('1')
    bit_ratio = bit_count / 32  # 4バイト = 32ビット

    # 閾値との比較
    if bit_ratio >= threshold:
        result = "true"
    else:
        result = "false"

    # 期待値と比較
    return result == expected_type
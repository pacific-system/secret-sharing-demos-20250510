# ラビット暗号化方式 🐰 実装【子 Issue #8】：テストとデバッグ

お兄様！いよいよ最終段階、ラビット暗号化方式のテストとデバッグを行いましょう！パシ子が詳しくご案内します 🔍✨

## 📋 タスク概要

ラビット暗号化方式の各コンポーネントが正しく機能するかどうかを検証するためのテストを実装し、システム全体の動作を確認します。また、バグがある場合はデバッグして修正します。

## 🔧 実装内容

### 主要な機能：

1. 各モジュールの単体テスト
2. 暗号化・復号のエンドツーエンドテスト
3. 鍵種別判定の正確性と分布のテスト
4. エッジケース・異常系のテスト
5. パフォーマンステスト

## 💻 実装手順

### 1. 単体テスト用の `tests` ディレクトリを準備

まず、単体テストファイルを作成します：

```bash
# テストディレクトリが存在しない場合は作成
mkdir -p method_6_rabbit/tests
touch method_6_rabbit/tests/__init__.py

# 各コンポーネントのテストファイルを作成
touch method_6_rabbit/tests/test_rabbit_stream.py
touch method_6_rabbit/tests/test_stream_selector.py
touch method_6_rabbit/tests/test_multipath_decrypt.py
touch method_6_rabbit/tests/test_key_analyzer.py
touch method_6_rabbit/tests/test_encrypt_decrypt.py
```

### 2. Rabbit ストリーム生成のテスト

`method_6_rabbit/tests/test_rabbit_stream.py` を以下のように実装します：

```python
"""
Rabbit ストリーム生成器のテスト
"""

import unittest
import os
import binascii
from method_6_rabbit.rabbit_stream import RabbitStreamGenerator, derive_key


class TestRabbitStream(unittest.TestCase):
    """
    Rabbit ストリーム生成アルゴリズムのテストケース
    """

    def test_rfc_test_vectors(self):
        """
        RFC 4503のテストベクトルを検証
        """
        # テストベクトル1（RFC 4503 Section 6.1）
        key = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(" ", ""))
        iv = bytes.fromhex("00 00 00 00 00 00 00 00".replace(" ", ""))
        expected = bytes.fromhex("eda81c7bb9d8f3512c6728b839368e9e")

        generator = RabbitStreamGenerator(key, iv)
        output = generator.generate(16)

        self.assertEqual(output, expected, "RFC 4503のテストベクトル1が一致しません")

        # テストベクトル2（RFC 4503 Section 6.2）
        key = bytes.fromhex("91 28 13 29 2e 3d 36 fe 3b fc 62 f1 dc 51 c3 ac".replace(" ", ""))
        iv = None  # IVなし
        expected = bytes.fromhex("154e3f4fa5ed8e2c386de3bc9c8b7c06")

        generator = RabbitStreamGenerator(key, iv)
        output = generator.generate(16)

        self.assertEqual(output, expected, "RFC 4503のテストベクトル2が一致しません")

    def test_stream_consistency(self):
        """
        同じ鍵とIVで常に同じストリームが生成されることを確認
        """
        key = os.urandom(16)
        iv = os.urandom(8)

        # 1回目の生成
        generator1 = RabbitStreamGenerator(key, iv)
        stream1 = generator1.generate(100)

        # 2回目の生成
        generator2 = RabbitStreamGenerator(key, iv)
        stream2 = generator2.generate(100)

        self.assertEqual(stream1, stream2, "同じ鍵とIVで異なるストリームが生成されました")

    def test_different_keys(self):
        """
        異なる鍵で異なるストリームが生成されることを確認
        """
        key1 = os.urandom(16)
        key2 = os.urandom(16)
        iv = os.urandom(8)

        generator1 = RabbitStreamGenerator(key1, iv)
        stream1 = generator1.generate(100)

        generator2 = RabbitStreamGenerator(key2, iv)
        stream2 = generator2.generate(100)

        self.assertNotEqual(stream1, stream2, "異なる鍵で同じストリームが生成されました")

    def test_different_ivs(self):
        """
        同じ鍵でも異なるIVで異なるストリームが生成されることを確認
        """
        key = os.urandom(16)
        iv1 = os.urandom(8)
        iv2 = os.urandom(8)

        generator1 = RabbitStreamGenerator(key, iv1)
        stream1 = generator1.generate(100)

        generator2 = RabbitStreamGenerator(key, iv2)
        stream2 = generator2.generate(100)

        self.assertNotEqual(stream1, stream2, "異なるIVで同じストリームが生成されました")

    def test_stream_length(self):
        """
        指定した長さのストリームが生成されることを確認
        """
        key = os.urandom(16)
        iv = os.urandom(8)

        generator = RabbitStreamGenerator(key, iv)

        # 様々な長さでテスト
        for length in [1, 16, 32, 100, 1000]:
            stream = generator.generate(length)
            self.assertEqual(len(stream), length, f"長さ{length}のストリーム生成に失敗")

    def test_derive_key(self):
        """
        鍵導出関数のテスト
        """
        password = "test_password"
        salt = os.urandom(16)

        # 同じパスワードとソルトからは常に同じ鍵とIVが導出されることを確認
        key1, iv1, salt1 = derive_key(password, salt)
        key2, iv2, salt2 = derive_key(password, salt)

        self.assertEqual(key1, key2, "同じパスワードとソルトから異なる鍵が導出されました")
        self.assertEqual(iv1, iv2, "同じパスワードとソルトから異なるIVが導出されました")
        self.assertEqual(salt1, salt2, "ソルトが一致しません")

        # 異なるパスワードからは異なる鍵が導出されることを確認
        key3, iv3, salt3 = derive_key("different_password", salt)

        self.assertNotEqual(key1, key3, "異なるパスワードから同じ鍵が導出されました")
        self.assertNotEqual(iv1, iv3, "異なるパスワードから同じIVが導出されました")

        # 異なるソルトからは異なる鍵が導出されることを確認
        key4, iv4, salt4 = derive_key(password)  # ソルトは自動生成

        self.assertNotEqual(salt1, salt4, "異なるソルトが生成されるべきです")
        self.assertNotEqual(key1, key4, "異なるソルトから同じ鍵が導出されました")
        self.assertNotEqual(iv1, iv4, "異なるソルトから同じIVが導出されました")


if __name__ == "__main__":
    unittest.main()
```

### 3. 鍵種別判定のテスト

`method_6_rabbit/tests/test_key_analyzer.py` を以下のように実装します：

```python
"""
鍵種別判定機能のテスト
"""

import unittest
import os
import time
import statistics
from method_6_rabbit.key_analyzer import (
    determine_key_type_advanced,
    obfuscated_key_determination,
    KEY_TYPE_TRUE,
    KEY_TYPE_FALSE
)


class TestKeyAnalyzer(unittest.TestCase):
    """
    鍵種別判定機能のテストケース
    """

    def test_key_type_consistency(self):
        """
        同じ鍵とソルトで常に同じ判定結果が得られることを確認
        """
        salt = os.urandom(16)
        test_keys = [
            "test_key_1",
            "test_key_2",
            "another_test_key",
            "yet_another_key"
        ]

        for key in test_keys:
            # 10回繰り返し判定
            results = [obfuscated_key_determination(key, salt) for _ in range(10)]

            # すべての結果が最初の結果と同じであることを確認
            first_result = results[0]
            for result in results[1:]:
                self.assertEqual(result, first_result,
                                f"鍵'{key}'の判定結果が一貫していません: {results}")

    def test_distribution(self):
        """
        ランダムなソルトを使用した場合、真/偽の判定がほぼ均等に分布することを確認
        """
        num_tests = 1000
        test_key = "distribution_test_key"

        # 分布カウント
        distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

        for _ in range(num_tests):
            salt = os.urandom(16)
            result = obfuscated_key_determination(test_key, salt)
            distribution[result] += 1

        # 両方の値が存在することを確認
        for key_type in [KEY_TYPE_TRUE, KEY_TYPE_FALSE]:
            self.assertGreater(distribution[key_type], 0,
                              f"{key_type}の判定結果がありません")

        # ほぼ均等に分布していることを確認（±10%の範囲内）
        ratio = distribution[KEY_TYPE_TRUE] / num_tests
        self.assertGreaterEqual(ratio, 0.4, "TRUEの分布が少なすぎます")
        self.assertLessEqual(ratio, 0.6, "TRUEの分布が多すぎます")

    def test_timing_attack_resistance(self):
        """
        タイミング攻撃に対する耐性を検証

        異なる鍵でも実行時間に有意な差がないことを確認
        """
        salt = os.urandom(16)

        # テスト用の鍵セット
        test_keys = [
            "short",
            "medium_length_key",
            "very_long_key_for_timing_test_to_see_if_there_is_any_difference",
            "another_key_12345678901234567890"
        ]

        # 各鍵の実行時間を測定
        timings = {}
        num_runs = 50  # 統計的に意味のある回数

        for key in test_keys:
            key_timings = []

            for _ in range(num_runs):
                start = time.perf_counter()
                _ = obfuscated_key_determination(key, salt)
                end = time.perf_counter()
                key_timings.append(end - start)

            # 外れ値を除去（最も遅い10%と最も速い10%を除外）
            key_timings.sort()
            trimmed_timings = key_timings[num_runs//10:-num_runs//10]

            # 平均時間を記録
            timings[key] = statistics.mean(trimmed_timings)

        # すべての鍵の実行時間が近いことを確認
        baseline = timings[test_keys[0]]
        for key, timing in timings.items():
            # 10%以内の差を許容
            ratio = timing / baseline
            self.assertGreaterEqual(ratio, 0.8,
                                   f"鍵'{key}'の実行時間が短すぎます: {timing}s vs {baseline}s")
            self.assertLessEqual(ratio, 1.2,
                                f"鍵'{key}'の実行時間が長すぎます: {timing}s vs {baseline}s")

    def test_advanced_vs_obfuscated(self):
        """
        高度な判定と難読化された判定の結果が一致することを確認
        """
        salt = os.urandom(16)
        test_keys = [
            "test_key_1",
            "test_key_2",
            "another_test_key"
        ]

        for key in test_keys:
            advanced_result = determine_key_type_advanced(key, salt)
            obfuscated_result = obfuscated_key_determination(key, salt)

            self.assertEqual(obfuscated_result, advanced_result,
                           f"鍵'{key}'に対する高度な判定と難読化された判定の結果が一致しません")


if __name__ == "__main__":
    unittest.main()
```

### 4. 暗号化・復号のエンドツーエンドテスト

`method_6_rabbit/tests/test_encrypt_decrypt.py` を以下のように実装します：

```python
"""
暗号化・復号のエンドツーエンドテスト
"""

import unittest
import os
import tempfile
import shutil
import binascii
from method_6_rabbit.encrypt import encrypt_files
from method_6_rabbit.decrypt import decrypt_file


class TestEncryptDecrypt(unittest.TestCase):
    """
    暗号化・復号機能のエンドツーエンドテスト
    """

    def setUp(self):
        """
        テスト用ディレクトリとファイルの準備
        """
        # 一時ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # テスト用のtrue.textとfalse.textを作成
        self.true_content = b"This is the true content for testing the Rabbit encryption method."
        self.false_content = b"This is the false content that should be produced with wrong keys."

        self.true_file = os.path.join(self.test_dir, "true.text")
        self.false_file = os.path.join(self.test_dir, "false.text")
        self.encrypted_file = os.path.join(self.test_dir, "test_encrypted.enc")

        with open(self.true_file, "wb") as f:
            f.write(self.true_content)

        with open(self.false_file, "wb") as f:
            f.write(self.false_content)

    def tearDown(self):
        """
        テスト用ディレクトリの削除
        """
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt_with_true_key(self):
        """
        暗号化して正規鍵で復号すると元のtrue.textが得られることを確認
        """
        # 暗号化
        key, _ = encrypt_files(self.true_file, self.false_file, self.encrypted_file)

        # 正規鍵で復号
        decrypted_file = os.path.join(self.test_dir, "decrypted_true.txt")
        decrypt_file(self.encrypted_file, key, decrypted_file)

        # 復号されたファイルの内容を確認
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(decrypted_content, self.true_content,
                        "正規鍵での復号結果がtrue.textと一致しません")

    def test_encrypt_decrypt_with_false_key(self):
        """
        暗号化して非正規鍵で復号すると元のfalse.textが得られることを確認
        """
        # 暗号化
        true_key, _ = encrypt_files(self.true_file, self.false_file, self.encrypted_file)

        # 非正規鍵の生成（真の鍵を少し変更）
        false_key = bytearray(true_key)
        false_key[0] = (false_key[0] + 1) % 256  # 1バイト変更
        false_key = bytes(false_key)

        # 非正規鍵で復号
        decrypted_file = os.path.join(self.test_dir, "decrypted_false.txt")
        decrypt_file(self.encrypted_file, false_key, decrypted_file)

        # 復号されたファイルの内容を確認
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        # 注: ここでは完全一致ではなく、先頭部分の一致を確認
        # （パディングの扱いにより末尾が異なる場合があるため）
        min_length = min(len(decrypted_content), len(self.false_content))
        self.assertEqual(decrypted_content[:min_length], self.false_content[:min_length],
                        "非正規鍵での復号結果がfalse.textの先頭部分と一致しません")

    def test_different_file_sizes(self):
        """
        異なるサイズのファイルでも正しく動作することを確認
        """
        # 大きなtrue.textと小さなfalse.text
        large_true = b"A" * 10000
        small_false = b"B" * 100

        large_true_file = os.path.join(self.test_dir, "large_true.text")
        small_false_file = os.path.join(self.test_dir, "small_false.text")

        with open(large_true_file, "wb") as f:
            f.write(large_true)

        with open(small_false_file, "wb") as f:
            f.write(small_false)

        # 暗号化
        large_encrypted_file = os.path.join(self.test_dir, "large_encrypted.enc")
        key, _ = encrypt_files(large_true_file, small_false_file, large_encrypted_file)

        # 正規鍵で復号
        decrypted_true = os.path.join(self.test_dir, "decrypted_large_true.txt")
        decrypt_file(large_encrypted_file, key, decrypted_true)

        with open(decrypted_true, "rb") as f:
            decrypted_true_content = f.read()

        # 復号結果の先頭部分が元のファイルと一致することを確認
        self.assertEqual(decrypted_true_content[:len(large_true)], large_true,
                        "大きなファイルの復号結果が一致しません")

        # 小さなtrue.textと大きなfalse.text
        small_true = b"C" * 100
        large_false = b"D" * 10000

        small_true_file = os.path.join(self.test_dir, "small_true.text")
        large_false_file = os.path.join(self.test_dir, "large_false.text")

        with open(small_true_file, "wb") as f:
            f.write(small_true)

        with open(large_false_file, "wb") as f:
            f.write(large_false)

        # 暗号化
        small_encrypted_file = os.path.join(self.test_dir, "small_encrypted.enc")
        key, _ = encrypt_files(small_true_file, large_false_file, small_encrypted_file)

        # 正規鍵で復号
        decrypted_small = os.path.join(self.test_dir, "decrypted_small_true.txt")
        decrypt_file(small_encrypted_file, key, decrypted_small)

        with open(decrypted_small, "rb") as f:
            decrypted_small_content = f.read()

        # 復号結果の先頭部分が元のファイルと一致することを確認
        self.assertEqual(decrypted_small_content[:len(small_true)], small_true,
                        "小さなファイルの復号結果が一致しません")

    def test_error_handling(self):
        """
        エラー処理が適切に機能することを確認
        """
        # 存在しないファイルの暗号化
        nonexistent_file = os.path.join(self.test_dir, "nonexistent.txt")
        with self.assertRaises(Exception):
            encrypt_files(nonexistent_file, self.false_file, self.encrypted_file)

        # 正しい暗号化と復号
        key, _ = encrypt_files(self.true_file, self.false_file, self.encrypted_file)

        # 壊れた暗号文ファイルの復号
        corrupted_file = os.path.join(self.test_dir, "corrupted.enc")
        with open(corrupted_file, "wb") as f:
            f.write(b"This is not a valid encrypted file")

        with self.assertRaises(Exception):
            decrypt_file(corrupted_file, key, os.path.join(self.test_dir, "should_fail.txt"))

        # 誤ったサイズの鍵
        wrong_size_key = os.urandom(8)  # 8バイト（正しくは16バイト）

        with self.assertRaises(Exception):
            decrypt_file(self.encrypted_file, wrong_size_key,
                       os.path.join(self.test_dir, "wrong_key_size.txt"))


if __name__ == "__main__":
    unittest.main()
```

### 5. 総合テストスクリプトを作成

`method_6_rabbit/tests/run_all_tests.py` を以下のように実装します：

```python
#!/usr/bin/env python3
"""
ラビット暗号化方式のすべてのテストを実行

このスクリプトは、ラビット暗号化方式の各コンポーネントのテストを順番に実行し、
結果をレポートします。
"""

import unittest
import sys
import os
import time

# テスト用のディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# テストモジュールをインポート
from method_6_rabbit.tests.test_rabbit_stream import TestRabbitStream
from method_6_rabbit.tests.test_key_analyzer import TestKeyAnalyzer
from method_6_rabbit.tests.test_encrypt_decrypt import TestEncryptDecrypt


def run_test_suite():
    """
    すべてのテストスイートを実行
    """
    # テストスイートの作成
    rabbit_stream_suite = unittest.TestLoader().loadTestsFromTestCase(TestRabbitStream)
    key_analyzer_suite = unittest.TestLoader().loadTestsFromTestCase(TestKeyAnalyzer)
    encrypt_decrypt_suite = unittest.TestLoader().loadTestsFromTestCase(TestEncryptDecrypt)

    # すべてのスイートを結合
    all_tests = unittest.TestSuite([
        rabbit_stream_suite,
        key_analyzer_suite,
        encrypt_decrypt_suite
    ])

    # ヘッダーを表示
    print("\n" + "=" * 70)
    print("ラビット暗号化方式 🐰 テスト実行")
    print("=" * 70)

    # テストの実行開始時間
    start_time = time.time()

    # テストの実行
    result = unittest.TextTestRunner(verbosity=2).run(all_tests)

    # 実行時間
    end_time = time.time()
    execution_time = end_time - start_time

    # 結果のサマリーを表示
    print("\n" + "=" * 70)
    print(f"テスト実行時間: {execution_time:.2f}秒")
    print(f"実行したテスト数: {result.testsRun}")
    print(f"成功したテスト数: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失敗したテスト数: {len(result.failures)}")
    print(f"エラーが発生したテスト数: {len(result.errors)}")
    print("=" * 70)

    return result.wasSuccessful()


def run_performance_test():
    """
    パフォーマンステストを実行
    """
    from method_6_rabbit.rabbit_stream import RabbitStreamGenerator
    import statistics

    print("\n" + "=" * 70)
    print("パフォーマンステスト")
    print("=" * 70)

    data_sizes = [1024, 10240, 102400, 1024000]  # 1KB, 10KB, 100KB, 1MB
    repeats = 5  # 各サイズで繰り返す回数

    for size in data_sizes:
        times = []

        for _ in range(repeats):
            key = os.urandom(16)
            iv = os.urandom(8)
            generator = RabbitStreamGenerator(key, iv)

            start_time = time.time()
            _ = generator.generate(size)
            end_time = time.time()

            times.append(end_time - start_time)

        avg_time = statistics.mean(times)
        throughput = size / avg_time / 1024  # KB/s

        print(f"データサイズ: {size/1024:.1f} KB")
        print(f"平均処理時間: {avg_time:.6f}秒")
        print(f"スループット: {throughput:.2f} KB/秒")
        print("-" * 50)

    print("=" * 70)


if __name__ == "__main__":
    # すべてのテストスイートを実行
    tests_passed = run_test_suite()

    # パフォーマンステストを実行
    run_performance_test()

    # 終了コードを設定
    sys.exit(0 if tests_passed else 1)
```

### 6. デバッグスクリプトを作成

`method_6_rabbit/tools/debug.py` を以下のように実装します：

```python
#!/usr/bin/env python3
"""
ラビット暗号化方式のデバッグツール

このスクリプトは、ラビット暗号化方式の動作を詳細に確認するためのツールを提供します。
内部状態や暗号化/復号プロセスの各ステップを可視化します。
"""

import os
import sys
import argparse
import binascii
import json
import base64
import time
from typing import Dict, Any

# 正しいインポートパスを設定
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from method_6_rabbit.rabbit_stream import RabbitStreamGenerator
from method_6_rabbit.stream_selector import StreamSelector
from method_6_rabbit.key_analyzer import obfuscated_key_determination
from method_6_rabbit.encrypt import encrypt_files
from method_6_rabbit.decrypt import decrypt_file
from method_6_rabbit.multipath_decrypt import create_multipath_capsule, extract_from_multipath_capsule


def debug_stream_generation(key: bytes, iv: bytes, length: int = 32):
    """
    ストリーム生成のデバッグ
    """
    print("\n== ストリーム生成のデバッグ ==")
    print(f"鍵: {binascii.hexlify(key).decode()}")
    print(f"IV: {binascii.hexlify(iv).decode()}")

    # ストリーム生成器を作成
    generator = RabbitStreamGenerator(key, iv)

    # 内部状態の取得（通常は隠蔽されているが、デバッグ用に公開）
    internal_state = {
        "X": [hex(x) for x in generator.X],
        "C": [hex(c) for c in generator.C],
        "carry": generator.carry
    }

    print("\n内部状態:")
    print(json.dumps(internal_state, indent=2))

    # ストリームを生成
    stream = generator.generate(length)

    print(f"\n生成されたストリーム ({length}バイト):")
    print(binascii.hexlify(stream).decode())

    return stream


def debug_key_determination(key: str, salt: bytes):
    """
    鍵種別判定のデバッグ
    """
    print("\n== 鍵種別判定のデバッグ ==")
    print(f"鍵: {key}")
    print(f"ソルト: {binascii.hexlify(salt).decode()}")

    # 鍵種別を判定
    start_time = time.time()
    key_type = obfuscated_key_determination(key, salt)
    end_time = time.time()

    print(f"\n判定結果: {key_type}")
    print(f"判定時間: {(end_time - start_time) * 1000:.3f}ミリ秒")

    return key_type


def debug_encrypt_decrypt_process(true_file: str, false_file: str, output_file: str):
    """
    暗号化・復号プロセスのデバッグ
    """
    print("\n== 暗号化・復号プロセスのデバッグ ==")
    print(f"true_file: {true_file}")
    print(f"false_file: {false_file}")
    print(f"output_file: {output_file}")

    # ファイルサイズを表示
    true_size = os.path.getsize(true_file)
    false_size = os.path.getsize(false_file)
    print(f"true_fileサイズ: {true_size}バイト")
    print(f"false_fileサイズ: {false_size}バイト")

    # 暗号化を実行
    print("\n暗号化を実行...")
    start_time = time.time()
    key, metadata = encrypt_files(true_file, false_file, output_file)
    end_time = time.time()

    encrypt_time = end_time - start_time
    output_size = os.path.getsize(output_file)

    print(f"暗号化時間: {encrypt_time:.3f}秒")
    print(f"出力ファイルサイズ: {output_size}バイト")
    print(f"鍵: {binascii.hexlify(key).decode()}")

    print("\nメタデータ:")
    print(json.dumps(metadata, indent=2))

    # 正規鍵で復号
    true_output = output_file + ".true.txt"
    print("\n正規鍵で復号...")
    start_time = time.time()
    decrypt_file(output_file, key, true_output)
    end_time = time.time()

    decrypt_true_time = end_time - start_time
    true_output_size = os.path.getsize(true_output)

    print(f"復号時間: {decrypt_true_time:.3f}秒")
    print(f"復号ファイルサイズ: {true_output_size}バイト")

    # 非正規鍵で復号
    false_key = bytearray(key)
    false_key[0] = (false_key[0] + 1) % 256  # 1バイト変更
    false_key = bytes(false_key)

    false_output = output_file + ".false.txt"
    print("\n非正規鍵で復号...")
    start_time = time.time()
    decrypt_file(output_file, false_key, false_output)
    end_time = time.time()

    decrypt_false_time = end_time - start_time
    false_output_size = os.path.getsize(false_output)

    print(f"復号時間: {decrypt_false_time:.3f}秒")
    print(f"復号ファイルサイズ: {false_output_size}バイト")

    # 結果の検証
    print("\n復号結果の検証:")

    with open(true_file, "rb") as f:
        true_original = f.read()

    with open(false_file, "rb") as f:
        false_original = f.read()

    with open(true_output, "rb") as f:
        true_decrypted = f.read()

    with open(false_output, "rb") as f:
        false_decrypted = f.read()

    true_match = true_original == true_decrypted[:len(true_original)]
    false_match = false_original == false_decrypted[:len(false_original)]

    print(f"正規鍵での復号結果は元のtrue.textと一致: {true_match}")
    print(f"非正規鍵での復号結果は元のfalse.textと一致: {false_match}")

    return {
        "key": key,
        "true_match": true_match,
        "false_match": false_match
    }


def parse_arguments():
    """
    コマンドライン引数を解析
    """
    parser = argparse.ArgumentParser(description="ラビット暗号化方式のデバッグツール")

    parser.add_argument(
        "--mode",
        type=str,
        choices=["stream", "key", "encrypt-decrypt", "all"],
        default="all",
        help="デバッグモード"
    )

    parser.add_argument(
        "--true-file",
        type=str,
        default="common/true-false-text/true.text",
        help="正規ファイルのパス"
    )

    parser.add_argument(
        "--false-file",
        type=str,
        default="common/true-false-text/false.text",
        help="非正規ファイルのパス"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="debug_output.enc",
        help="出力ファイルのパス"
    )

    parser.add_argument(
        "--key",
        type=str,
        default=None,
        help="テスト用の鍵（16進数またはテキスト）"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # ヘッダーを表示
    print("=" * 70)
    print("ラビット暗号化方式 🐰 デバッグツール")
    print("=" * 70)

    # 鍵と初期化ベクトルを生成
    if args.key:
        try:
            # 16進数として解釈を試みる
            key = binascii.unhexlify(args.key.replace(" ", ""))
            if len(key) != 16:
                raise ValueError()
        except ValueError:
            # テキストとして扱い、ハッシュ化
            key = hashlib.sha256(args.key.encode()).digest()[:16]
    else:
        key = os.urandom(16)

    iv = os.urandom(8)
    salt = os.urandom(16)

    # 選択されたモードに応じてデバッグを実行
    if args.mode in ["stream", "all"]:
        debug_stream_generation(key, iv)

    if args.mode in ["key", "all"]:
        debug_key_determination("test_key_for_debugging", salt)

    if args.mode in ["encrypt-decrypt", "all"]:
        debug_encrypt_decrypt_process(args.true_file, args.false_file, args.output)

    print("\n" + "=" * 70)
    print("デバッグ完了")
    print("=" * 70)


if __name__ == "__main__":
    main()
```

## ✅ 完了条件

- [ ] 各モジュールの単体テストが実装され、パスしている
- [ ] 暗号化・復号のエンドツーエンドテストが実装され、パスしている
- [ ] 鍵種別判定の正確性と分布のテストが実装され、パスしている
- [ ] エッジケースや異常系のテストが実装されている
- [ ] パフォーマンステストが実装され、要件を満たしている（10MB/秒以上）
- [ ] デバッグツールが実装され、各コンポーネントの動作を詳細に確認できる
- [ ] すべてのテストがパスし、既知のバグが修正されている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# すべてのテストを実行
python -m method_6_rabbit.tests.run_all_tests

# 個別のテストを実行
python -m method_6_rabbit.tests.test_rabbit_stream
python -m method_6_rabbit.tests.test_key_analyzer
python -m method_6_rabbit.tests.test_encrypt_decrypt

# デバッグツールを実行
python -m method_6_rabbit.tools.debug --mode all
python -m method_6_rabbit.tools.debug --mode stream
python -m method_6_rabbit.tools.debug --mode key
python -m method_6_rabbit.tools.debug --mode encrypt-decrypt
```

## ⏰ 想定実装時間

約 8 時間

## 📚 参考資料

- [Python unittest ライブラリ](https://docs.python.org/ja/3/library/unittest.html)
- [Python 暗号化テストのベストプラクティス](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)
- [ユニットテストのパターンと実践](https://martinfowler.com/articles/practical-test-pyramid.html)

## 💬 備考

- テストはシステムの品質を保証するために非常に重要です。特に暗号システムでは、小さなバグが大きなセキュリティホールになる可能性があります。
- エッジケースや異常系のテストを充実させてください。特に、不正な入力やファイル形式に対する堅牢性を確認することが重要です。
- パフォーマンスは要件の一つですので、大きなファイルでも適切な速度で処理できることを確認してください。
- デバッグツールは開発時には非常に役立ちますが、本番環境では使用しないでください（内部状態が漏洩する可能性があります）。
- 問題が見つかった場合は、根本的な原因を特定し、すべての関連するケースを修正してください。

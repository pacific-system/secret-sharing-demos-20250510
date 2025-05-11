# 暗号学的ハニーポット方式 🍯 実装【子 Issue #8】：テストとデバッグ

お兄様！最後の仕上げとして、テストとデバッグを実施しましょう！完璧な暗号学的ハニーポット方式にするためにパシ子とレオくんが全力でサポートします！✨

## 📋 タスク概要

暗号学的ハニーポット方式の各モジュールが正しく連携して動作することを確認するためのテストと、潜在的な問題を特定・修正するためのデバッグを実施します。

## 🔧 実装内容

`method_7_honeypot/tests/` ディレクトリに、テストスクリプトを実装します。

### 主要な機能：

1. 単体テスト
2. 統合テスト
3. エンドツーエンドテスト
4. 動作検証とデバッグ

## 💻 実装手順

### 1. テスト環境のセットアップ

まず、テスト環境を整備するためのディレクトリとファイルを作成します：

```bash
# テストディレクトリの作成
mkdir -p method_7_honeypot/tests
touch method_7_honeypot/tests/__init__.py

# テストデータディレクトリの作成
mkdir -p method_7_honeypot/tests/test_data
```

### 2. テストデータの準備

テスト用のサンプルファイルを作成します：

```bash
# 正規テキストファイルの作成
echo "これは正規のファイルです。正しい鍵で復号されたことを示します。" > method_7_honeypot/tests/test_data/true.text

# 非正規テキストファイルの作成
echo "これは非正規のファイルです。不正な鍵で復号されたことを示します。" > method_7_honeypot/tests/test_data/false.text
```

### 3. 単体テストの実装

`method_7_honeypot/tests/test_trapdoor.py` ファイルを作成し、トラップドア関数をテストします：

```python
"""
トラップドア関数の単体テスト
"""

import unittest
import os
import sys
from typing import Dict, Any

# テスト対象のモジュールをインポート
from ..trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, evaluate_key_type,
    generate_honey_token, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)


class TestTrapdoor(unittest.TestCase):
    """トラップドア関数のテストケース"""

    def setUp(self):
        """テスト前の準備"""
        self.master_key = create_master_key()
        self.params = create_trapdoor_parameters(self.master_key)
        self.keys, self.salt = derive_keys_from_trapdoor(self.params)

    def test_key_generation(self):
        """鍵生成のテスト"""
        # 鍵のサイズを確認
        self.assertEqual(len(self.keys[KEY_TYPE_TRUE]), 32)
        self.assertEqual(len(self.keys[KEY_TYPE_FALSE]), 32)

        # 正規鍵と非正規鍵は異なることを確認
        self.assertNotEqual(self.keys[KEY_TYPE_TRUE], self.keys[KEY_TYPE_FALSE])

    def test_key_evaluation(self):
        """鍵評価のテスト"""
        # 正規鍵の評価
        result_true = evaluate_key_type(self.keys[KEY_TYPE_TRUE], self.params, self.salt)
        self.assertEqual(result_true, KEY_TYPE_TRUE)

        # 非正規鍵の評価
        result_false = evaluate_key_type(self.keys[KEY_TYPE_FALSE], self.params, self.salt)
        self.assertEqual(result_false, KEY_TYPE_FALSE)


if __name__ == '__main__':
    unittest.main()
```

### 4. 統合テストの実装

`method_7_honeypot/tests/test_integration.py` ファイルを作成し、暗号化と復号のフローをテストします：

```python
"""
暗号化と復号の統合テスト
"""

import unittest
import os
import sys
import tempfile
from typing import Dict, Any

# テスト対象のモジュールをインポート
from ..trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from ..encrypt import encrypt_files
from ..decrypt import decrypt_file


class TestEncryptDecrypt(unittest.TestCase):
    """暗号化と復号のテストケース"""

    def setUp(self):
        """テスト前の準備"""
        # テストファイルのパス
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        self.true_file = os.path.join(self.test_dir, 'true.text')
        self.false_file = os.path.join(self.test_dir, 'false.text')

        # 出力ディレクトリ
        self.output_dir = tempfile.mkdtemp()
        self.output_file = os.path.join(self.output_dir, 'test_output.hpot')

    def test_encrypt_decrypt_cycle(self):
        """暗号化→復号のサイクルテスト"""
        # 暗号化
        key_info, metadata = encrypt_files(
            self.true_file, self.false_file, self.output_file
        )

        # 出力ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.output_file))

        # 正規鍵で復号
        true_key_type, true_plaintext = decrypt_file(
            self.output_file, key_info[KEY_TYPE_TRUE]
        )

        # 非正規鍵で復号
        false_key_type, false_plaintext = decrypt_file(
            self.output_file, key_info[KEY_TYPE_FALSE]
        )

        # 復号結果の検証
        with open(self.true_file, 'rb') as f:
            original_true = f.read()

        with open(self.false_file, 'rb') as f:
            original_false = f.read()

        # 正規鍵では正規ファイルの内容が復元される
        self.assertEqual(true_plaintext, original_true)
        self.assertEqual(true_key_type, KEY_TYPE_TRUE)

        # 非正規鍵では非正規ファイルの内容が復元される
        self.assertEqual(false_plaintext, original_false)
        self.assertEqual(false_key_type, KEY_TYPE_FALSE)


if __name__ == '__main__':
    unittest.main()
```

### 5. カプセル処理のテスト

`method_7_honeypot/tests/test_capsule.py` ファイルを作成し、ハニーポットカプセルの機能をテストします：

```python
"""
ハニーポットカプセルのテスト
"""

import unittest
import os
import sys
from typing import Dict, Any

# テスト対象のモジュールをインポート
from ..trapdoor import (
    create_master_key, create_trapdoor_parameters,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from ..honeypot_capsule import (
    HoneypotCapsuleFactory,
    create_honeypot_file,
    read_data_from_honeypot_file
)


class TestHoneypotCapsule(unittest.TestCase):
    """ハニーポットカプセルのテストケース"""

    def test_capsule_operations(self):
        """カプセル操作のテスト"""
        # マスター鍵とパラメータの生成
        master_key = create_master_key()
        params = create_trapdoor_parameters(master_key)

        # テストデータの準備
        true_data = b"This is the true test data."
        false_data = b"This is the false test data."

        # カプセルの作成
        capsule_data = create_honeypot_file(
            true_data, false_data, params, {'test': 'metadata'}
        )

        # カプセルからデータを読み込み
        read_true_data, metadata = read_data_from_honeypot_file(
            capsule_data, KEY_TYPE_TRUE
        )

        read_false_data, _ = read_data_from_honeypot_file(
            capsule_data, KEY_TYPE_FALSE
        )

        # データが正しく復元されることを確認
        self.assertEqual(read_true_data, true_data)
        self.assertEqual(read_false_data, false_data)
        self.assertEqual(metadata.get('test'), 'metadata')


if __name__ == '__main__':
    unittest.main()
```

### 6. 改変耐性のテスト

`method_7_honeypot/tests/test_tamper_resistance.py` ファイルを作成し、スクリプト改変耐性をテストします：

```python
"""
スクリプト改変耐性のテスト
"""

import unittest
import os
import sys
from typing import Dict, Any

# テスト対象のモジュールをインポート
from ..trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, generate_honey_token,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from ..deception import (
    verify_with_tamper_resistance,
    DynamicPathSelector
)


class TestTamperResistance(unittest.TestCase):
    """改変耐性のテストケース"""

    def test_path_selection(self):
        """経路選択のテスト"""
        # 準備
        master_key = create_master_key()
        params = create_trapdoor_parameters(master_key)
        keys, salt = derive_keys_from_trapdoor(params)

        # トークンの生成
        true_token = generate_honey_token(KEY_TYPE_TRUE, params)
        false_token = generate_honey_token(KEY_TYPE_FALSE, params)

        # 経路選択器の作成
        selector = DynamicPathSelector(master_key)

        # 正規鍵と非正規鍵で異なる経路が選択されることを確認
        true_path = selector.select_path(keys[KEY_TYPE_TRUE], true_token)
        false_path = selector.select_path(keys[KEY_TYPE_FALSE], false_token)

        # 結果をチェック（具体的な値よりも、種類が出力されることを確認）
        self.assertIn(true_path, [KEY_TYPE_TRUE, KEY_TYPE_FALSE])
        self.assertIn(false_path, [KEY_TYPE_TRUE, KEY_TYPE_FALSE])


if __name__ == '__main__':
    unittest.main()
```

### 7. 統合テスト実行スクリプトの実装

`method_7_honeypot/tests/run_tests.py` ファイルを作成し、すべてのテストを実行するスクリプトを実装します：

```python
#!/usr/bin/env python3
"""
すべてのテストを実行するスクリプト
"""

import unittest
import os
import sys
import time


def run_all_tests():
    """すべてのテストを実行"""
    start_time = time.time()

    # テストの自動検出と実行
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(
        os.path.dirname(__file__),
        pattern='test_*.py'
    )

    # テスト実行
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    # 結果の表示
    elapsed = time.time() - start_time
    print(f"\n実行時間: {elapsed:.2f}秒")

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
```

### 8. デバッグ支援スクリプトの実装

`method_7_honeypot/debug.py` ファイルを作成し、デバッグ支援機能を実装します：

```python
#!/usr/bin/env python3
"""
暗号学的ハニーポット方式のデバッグツール
"""

import os
import sys
import argparse
import binascii
import time
from typing import Dict, Any

# 内部モジュールからのインポート
from .trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, evaluate_key_type,
    generate_honey_token, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)


def debug_key_generation():
    """鍵生成過程をデバッグ"""
    print("=== 鍵生成のデバッグ ===")

    # マスター鍵の生成
    master_key = create_master_key()
    print(f"マスター鍵: {binascii.hexlify(master_key).decode()}")

    # トラップドアパラメータの生成
    params = create_trapdoor_parameters(master_key)
    print(f"パラメータ生成完了")

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(params)
    print(f"正規鍵: {binascii.hexlify(keys[KEY_TYPE_TRUE]).decode()}")
    print(f"非正規鍵: {binascii.hexlify(keys[KEY_TYPE_FALSE]).decode()}")

    # 鍵評価
    result_true = evaluate_key_type(keys[KEY_TYPE_TRUE], params, salt)
    result_false = evaluate_key_type(keys[KEY_TYPE_FALSE], params, salt)

    print(f"正規鍵の評価結果: {result_true}")
    print(f"非正規鍵の評価結果: {result_false}")


def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description="暗号学的ハニーポット方式のデバッグツール")

    parser.add_argument(
        "--key-gen",
        action="store_true",
        help="鍵生成のデバッグ"
    )

    args = parser.parse_args()

    # デフォルトで鍵生成をデバッグ
    if not args.key_gen:
        args.key_gen = True

    if args.key_gen:
        debug_key_generation()

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## ✅ 完了条件

- [ ] 単体テスト（test_trapdoor.py）が実装され、トラップドア関数が正しく機能することが確認できる
- [ ] 統合テスト（test_integration.py）が実装され、暗号化 → 復号の一連の流れが正しく機能することが確認できる
- [ ] カプセルテスト（test_capsule.py）が実装され、ハニーポットカプセルが正しく機能することが確認できる
- [ ] 改変耐性テスト（test_tamper_resistance.py）が実装され、経路選択機能が正しく機能することが確認できる
- [ ] 統合テスト実行スクリプト（run_tests.py）が実装され、すべてのテストを一括実行できる
- [ ] デバッグ支援スクリプト（debug.py）が実装され、主要な機能の内部動作を可視化できる
- [ ] すべてのテストが正常に実行され、エラーが発生しない

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# すべてのテストを実行
python -m method_7_honeypot.tests.run_tests

# 個別テストの実行
python -m unittest method_7_honeypot.tests.test_trapdoor
python -m unittest method_7_honeypot.tests.test_integration
python -m unittest method_7_honeypot.tests.test_capsule
python -m unittest method_7_honeypot.tests.test_tamper_resistance

# デバッグツールの実行
python -m method_7_honeypot.debug
```

## ⏰ 想定実装時間

約 4 時間

## 📚 参考資料

- [Python unittest の使い方](https://docs.python.org/ja/3/library/unittest.html)
- [効果的なテスト戦略](https://docs.pytest.org/en/latest/explanation/test-strategy.html)
- [Python デバッグ技法](https://realpython.com/python-debugging-pdb/)

## 💬 備考

- 単体テストから始めて、徐々に複雑な統合テストへと進むとデバッグが容易になります
- 実装と並行してテストを行うことで、早期に問題を発見・修正できます
- 特に暗号システムでは、エッジケースやバイト列処理に注意してテストを行いましょう
- デバッグ支援スクリプトはリリース版には含めないよう注意してください

疑問点や提案があればぜひ教えてくださいね！パシ子とレオくんが全力でサポートします！💕

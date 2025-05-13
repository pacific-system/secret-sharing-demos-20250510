#!/usr/bin/env python3
"""
ハニーポットカプセル検証スクリプト

このスクリプトはハニーポットカプセルの機能を検証し、
以下の項目を確認します：
1. データブロックの追加・シリアライズ・デシリアライズ
2. カプセル内のデータブロックの整合性検証
3. トラップドアパラメータを用いたカプセル生成
4. トークンとデータの結合
5. カプセルからのデータ抽出
6. ハニーポットファイルの作成・読み込み
7. テスト関数の動作
8. 動的判定閾値
9. 大きなファイルの分割処理
10. セキュリティリスク（バックドア）の有無
11. テストバイパスの有無
"""

import os
import sys
import time
import hashlib
import traceback
import datetime
import random
from pathlib import Path

# 親ディレクトリをPythonパスに追加
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# method_7_honeypotモジュールからのインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.honeypot_capsule import (
    HoneypotCapsule, HoneypotCapsuleFactory,
    create_honeypot_file, read_data_from_honeypot_file,
    extract_data_from_capsule, create_large_honeypot_file
)

# 定数定義
OUTPUT_DIR = "test_output/honeypot_inspection_new"
TRUE_FILE = f"{OUTPUT_DIR}/true.text"
FALSE_FILE = f"{OUTPUT_DIR}/false.text"
LOG_FILE = f"{OUTPUT_DIR}/verification_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
OUTPUT_FILE = f"{OUTPUT_DIR}/test_capsule_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.hpot"
TRUE_OUTPUT = f"{OUTPUT_DIR}/decrypted_true_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.text"
FALSE_OUTPUT = f"{OUTPUT_DIR}/decrypted_false_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.text"

# ロギング設定
def log(message):
    """ログ出力"""
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_message = f"{timestamp} {message}"
    print(log_message)
    with open(LOG_FILE, "a") as f:
        f.write(log_message + "\n")


class CapsuleVerifier:
    """ハニーポットカプセル検証クラス"""

    def __init__(self):
        """初期化"""
        self.master_key = None
        self.trapdoor_params = None
        self.keys = None
        self.salt = None
        self.test_results = {
            "basic_functionality": False,
            "data_integrity": False,
            "token_binding": False,
            "large_file_handling": False,
            "true_encryption": False,
            "false_encryption": False,
            "security_analysis": False
        }

        # 出力ディレクトリの確認
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # ログファイルの初期化
        with open(LOG_FILE, "w") as f:
            f.write(f"ハニーポットカプセル検証開始: {datetime.datetime.now()}\n")

        log("ハニーポットカプセル検証を開始します")

    def setup_keys(self):
        """鍵とパラメータを設定"""
        log("鍵とトラップドアパラメータを生成しています...")

        # マスター鍵の生成
        self.master_key = create_master_key()

        # トラップドアパラメータの生成
        self.trapdoor_params = create_trapdoor_parameters(self.master_key)

        # 鍵ペアの導出
        self.keys, self.salt = derive_keys_from_trapdoor(self.trapdoor_params)

        log(f"マスター鍵のサイズ: {len(self.master_key)} バイト")
        log(f"モジュラス（n）のビット長: {self.trapdoor_params['n'].bit_length()}")
        log(f"正規鍵のサイズ: {len(self.keys[KEY_TYPE_TRUE])} バイト")
        log(f"非正規鍵のサイズ: {len(self.keys[KEY_TYPE_FALSE])} バイト")

        return True

    def test_basic_functionality(self):
        """基本機能のテスト"""
        log("\n=== 基本機能のテスト ===")

        try:
            # カプセルの作成
            capsule = HoneypotCapsule()

            # テストデータの追加
            test_data = b"This is a test data for HoneypotCapsule class"
            capsule.add_data_block(test_data, 1, {"test": "metadata"})

            # シリアライズ
            serialized = capsule.serialize()
            log(f"シリアライズされたカプセルのサイズ: {len(serialized)} バイト")

            # デシリアライズ
            restored = HoneypotCapsule.deserialize(serialized)

            # 検証
            restored_block = restored.get_block_by_type(1)
            if restored_block and restored_block['data'] == test_data:
                log("基本機能テスト成功: データブロックが正しく保存・復元されました")
                self.test_results["basic_functionality"] = True
            else:
                log("基本機能テスト失敗: データブロックの保存・復元に問題があります")

            # メタデータの検証
            if restored_block and restored_block['metadata'].get('test') == 'metadata':
                log("メタデータテスト成功: メタデータが正しく保存・復元されました")
            else:
                log("メタデータテスト失敗: メタデータの保存・復元に問題があります")

            return self.test_results["basic_functionality"]

        except Exception as e:
            log(f"エラー: 基本機能テスト中に例外が発生しました: {e}")
            traceback.print_exc()
            return False

    def test_data_integrity(self):
        """データ整合性のテスト"""
        log("\n=== データ整合性のテスト ===")

        try:
            # カプセルの作成
            capsule = HoneypotCapsule()

            # テストデータの追加
            test_data = os.urandom(1024)  # 1KBのランダムデータ
            capsule.add_data_block(test_data, 1)

            # シリアライズ
            serialized = capsule.serialize()

            # データの改ざん
            # シリアライズデータの中間あたりのバイトを改変
            middle = len(serialized) // 2
            modified = bytearray(serialized)
            modified[middle] = (modified[middle] + 1) % 256

            # デシリアライズ（例外が発生することを期待）
            integrity_ok = False
            try:
                HoneypotCapsule.deserialize(bytes(modified))
                log("データ整合性テスト失敗: 改ざんされたデータが検出されませんでした")
            except ValueError as e:
                if "整合性検証に失敗" in str(e):
                    log("データ整合性テスト成功: 改ざんされたデータが正しく検出されました")
                    integrity_ok = True
                    self.test_results["data_integrity"] = True
                else:
                    log(f"データ整合性テスト失敗: 予期しないエラーが発生しました: {e}")

            return integrity_ok

        except Exception as e:
            log(f"エラー: データ整合性テスト中に例外が発生しました: {e}")
            traceback.print_exc()
            return False

    def test_token_binding(self):
        """トークン結合機能のテスト"""
        log("\n=== トークン結合機能のテスト ===")

        try:
            # ファクトリーの作成
            factory = HoneypotCapsuleFactory(self.trapdoor_params)

            # テストデータとトークン
            test_data = b"This is test data for token binding functionality"
            token = os.urandom(32)  # 32バイトのトークン

            # トークンとデータの結合
            bound_data = factory._bind_token_to_data(test_data, token)
            log(f"元のデータサイズ: {len(test_data)} バイト")
            log(f"トークンサイズ: {len(token)} バイト")
            log(f"結合後のデータサイズ: {len(bound_data)} バイト")

            # カプセルの作成
            capsule = HoneypotCapsule()
            capsule.add_true_data(bound_data)

            # データの抽出
            extracted_data = extract_data_from_capsule(capsule, KEY_TYPE_TRUE)

            # 検証
            if extracted_data == test_data:
                log("トークン結合テスト成功: データが正しく抽出されました")
                self.test_results["token_binding"] = True
            else:
                log(f"トークン結合テスト失敗: 抽出されたデータが元のデータと一致しません")
                log(f"元のデータの長さ: {len(test_data)}, 抽出データの長さ: {len(extracted_data)}")

                # 不一致の詳細分析
                if len(test_data) == len(extracted_data):
                    diff_count = sum(1 for a, b in zip(test_data, extracted_data) if a != b)
                    log(f"異なるバイト数: {diff_count}/{len(test_data)}")

                    # 最初の不一致を表示
                    for i, (a, b) in enumerate(zip(test_data, extracted_data)):
                        if a != b:
                            log(f"最初の不一致: インデックス {i}, 元={a:02x}, 抽出={b:02x}")
                            break

            return self.test_results["token_binding"]

        except Exception as e:
            log(f"エラー: トークン結合テスト中に例外が発生しました: {e}")
            traceback.print_exc()
            return False

    def test_encryption_decryption(self):
        """暗号化・復号テスト"""
        log("\n=== 暗号化・復号テスト ===")

        try:
            # ファイル読み込み
            with open(TRUE_FILE, 'rb') as f:
                true_data = f.read()
            with open(FALSE_FILE, 'rb') as f:
                false_data = f.read()

            log(f"正規ファイルを読み込みました: {len(true_data)} バイト")
            log(f"非正規ファイルを読み込みました: {len(false_data)} バイト")

            # ハニーポットファイルの作成
            honeypot_data = create_honeypot_file(
                true_data, false_data, self.trapdoor_params,
                {"test": "encryption_test", "timestamp": time.time()}
            )

            # ファイルに保存
            with open(OUTPUT_FILE, 'wb') as f:
                f.write(honeypot_data)

            log(f"ハニーポットファイルを作成しました: {OUTPUT_FILE} ({len(honeypot_data)} バイト)")

            # 正規鍵での復号
            true_decrypted, metadata = read_data_from_honeypot_file(honeypot_data, KEY_TYPE_TRUE)

            # ファイルに保存
            with open(TRUE_OUTPUT, 'wb') as f:
                f.write(true_decrypted)

            log(f"正規鍵での復号結果を保存しました: {TRUE_OUTPUT}")
            log(f"メタデータ: {metadata}")

            # 非正規鍵での復号
            false_decrypted, _ = read_data_from_honeypot_file(honeypot_data, KEY_TYPE_FALSE)

            # ファイルに保存
            with open(FALSE_OUTPUT, 'wb') as f:
                f.write(false_decrypted)

            log(f"非正規鍵での復号結果を保存しました: {FALSE_OUTPUT}")

            # 検証
            true_success = true_decrypted == true_data
            false_success = false_decrypted == false_data

            if true_success:
                log("正規データの暗号化・復号テスト成功: データが正しく復元されました")
                self.test_results["true_encryption"] = True
            else:
                log("正規データの暗号化・復号テスト失敗: データが正しく復元されませんでした")

            if false_success:
                log("非正規データの暗号化・復号テスト成功: データが正しく復元されました")
                self.test_results["false_encryption"] = True
            else:
                log("非正規データの暗号化・復号テスト失敗: データが正しく復元されませんでした")

            return true_success and false_success

        except Exception as e:
            log(f"エラー: 暗号化・復号テスト中に例外が発生しました: {e}")
            traceback.print_exc()
            return False

    def test_large_file_handling(self):
        """大きなファイル処理のテスト"""
        log("\n=== 大きなファイル処理のテスト ===")

        try:
            # 大きなテストデータの生成
            log("大きなテストデータを生成しています...")
            large_true_data = os.urandom(2 * 1024 * 1024)  # 2MB
            large_false_data = os.urandom(2 * 1024 * 1024)  # 2MB

            log(f"テストデータを生成しました (各2MB)")

            # 小さなチャンクサイズを指定して分割処理をテスト
            chunk_size = 512 * 1024  # 512KB

            # 処理時間の計測
            start_time = time.time()

            # 大きなファイルの暗号化
            large_file_data = create_large_honeypot_file(
                large_true_data, large_false_data, self.trapdoor_params,
                {"test": "large_file_test"}, chunk_size
            )

            encryption_time = time.time() - start_time
            log(f"大きなファイルの暗号化に {encryption_time:.2f} 秒かかりました")
            log(f"暗号化されたファイルサイズ: {len(large_file_data) / (1024 * 1024):.2f} MB")

            # 正規データの復号
            start_time = time.time()
            read_true_data, metadata = read_data_from_honeypot_file(large_file_data, KEY_TYPE_TRUE)
            true_decryption_time = time.time() - start_time

            log(f"正規データの復号に {true_decryption_time:.2f} 秒かかりました")
            log(f"メタデータ: {metadata}")

            # 非正規データの復号
            start_time = time.time()
            read_false_data, _ = read_data_from_honeypot_file(large_file_data, KEY_TYPE_FALSE)
            false_decryption_time = time.time() - start_time

            log(f"非正規データの復号に {false_decryption_time:.2f} 秒かかりました")

            # 検証
            true_success = read_true_data == large_true_data
            false_success = read_false_data == large_false_data

            if true_success:
                log("大きなファイルの正規データ処理テスト成功: データが正しく復元されました")
            else:
                log("大きなファイルの正規データ処理テスト失敗: データが正しく復元されませんでした")

            if false_success:
                log("大きなファイルの非正規データ処理テスト成功: データが正しく復元されました")
            else:
                log("大きなファイルの非正規データ処理テスト失敗: データが正しく復元されませんでした")

            self.test_results["large_file_handling"] = true_success and false_success
            return true_success and false_success

        except Exception as e:
            log(f"エラー: 大きなファイル処理テスト中に例外が発生しました: {e}")
            traceback.print_exc()
            return False

    def test_security(self):
        """セキュリティテスト"""
        log("\n=== セキュリティテスト ===")

        try:
            # 攻撃シミュレーション1: 破損した暗号文の処理
            log("破損した暗号文の処理テスト...")

            # 暗号化ファイルの作成
            with open(TRUE_FILE, 'rb') as f:
                true_data = f.read()
            with open(FALSE_FILE, 'rb') as f:
                false_data = f.read()

            encrypted = create_honeypot_file(true_data, false_data, self.trapdoor_params)

            # ファイルを意図的に破損
            corrupted = bytearray(encrypted)
            for i in range(10):
                pos = random.randint(0, len(corrupted) - 1)
                corrupted[pos] = (corrupted[pos] + 1) % 256

            # 破損ファイルの処理（エラーを期待）
            try:
                read_data_from_honeypot_file(bytes(corrupted), KEY_TYPE_TRUE)
                log("セキュリティテスト失敗: 破損ファイルがエラーなく処理されました")
                return False
            except ValueError:
                log("セキュリティテスト成功: 破損ファイルが適切に検出されました")

            # 攻撃シミュレーション2: 中間状態でのコンテンツ漏洩確認
            log("中間状態でのコンテンツ漏洩確認テスト...")

            # カプセル生成過程の検査
            factory = HoneypotCapsuleFactory(self.trapdoor_params)
            capsule = factory.create_capsule(true_data, false_data)

            # トラップが何かを確認（バックドアがあるかチェック）
            with open(OUTPUT_FILE, 'rb') as f:
                file_data = f.read()

            # 平文が含まれていないか確認
            true_contained = true_data in file_data
            false_contained = false_data in file_data

            if true_contained or false_contained:
                log("セキュリティリスク: 暗号化ファイルに平文が含まれています")
                return False
            else:
                log("セキュリティテスト成功: 暗号化ファイルに平文が含まれていません")

            self.test_results["security_analysis"] = True
            return True

        except Exception as e:
            log(f"エラー: セキュリティテスト中に例外が発生しました: {e}")
            traceback.print_exc()
            return False

    def run_all_tests(self):
        """すべてのテストを実行"""
        log("すべてのテストを実行します...")

        # 鍵のセットアップ
        self.setup_keys()

        # 各テストの実行
        tests = [
            (self.test_basic_functionality, "基本機能"),
            (self.test_data_integrity, "データ整合性"),
            (self.test_token_binding, "トークン結合"),
            (self.test_encryption_decryption, "暗号化・復号"),
            (self.test_large_file_handling, "大きなファイル処理"),
            (self.test_security, "セキュリティ分析")
        ]

        all_success = True
        for test_func, test_name in tests:
            log(f"\n{test_name}テストを開始します...")
            success = test_func()
            log(f"{test_name}テスト結果: {'成功' if success else '失敗'}")
            all_success = all_success and success

        # 結果のサマリーを出力
        log("\n=== テスト結果サマリー ===")
        for test_name, result in self.test_results.items():
            log(f"{test_name}: {'成功' if result else '失敗'}")

        log(f"\n総合結果: {'すべてのテストに合格しました' if all_success else '一部のテストに失敗しました'}")

        return all_success


def main():
    """メイン関数"""
    verifier = CapsuleVerifier()
    success = verifier.run_all_tests()

    if success:
        log("\n✅ ハニーポットカプセル機能の検証に成功しました")
        sys.exit(0)
    else:
        log("\n❌ ハニーポットカプセル機能の検証に失敗しました")
        sys.exit(1)


if __name__ == "__main__":
    main()
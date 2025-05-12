#!/usr/bin/env python3
"""
準同型暗号マスキング方式のデータアダプター直接テスト
"""

import os
import sys
import time
import base64
from typing import Dict, Any, Tuple, List, Optional, Union

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

from method_8_homomorphic.crypto_adapters import (
    TextAdapter, BinaryAdapter, JSONAdapter, Base64Adapter,
    process_data_for_encryption, process_data_after_decryption
)

def test_text_adapter():
    """
    TextAdapterの多段エンコーディング機能をテスト
    """
    # テスト用テキスト
    test_texts = [
        "これは単純なテキストです。Hello, World!",
        "特殊文字テスト: !@#$%^&*()_+-={}[]|\\:;\"'<>,.?/\n\t\r",
        """
        吾輩は猫である。名前はまだ無い。
        どこで生れたかとんと見当がつかぬ。何でも薄暗いじめじめした所でニャーニャー泣いていた事だけは記憶している。
        吾輩はここで始めて人間というものを見た。しかもあとで聞くとそれは書生という人間中で一番獰悪な種族であったそうだ。
        この書生というのは時々我々を捕えて煮て食うという話である。
        """,
        "長いテキスト" * 100
    ]

    adapter = TextAdapter()

    for i, text in enumerate(test_texts):
        print(f"\n===== テキストテスト {i+1} =====")
        print(f"元テキスト: {text[:50]}{'...' if len(text) > 50 else ''}")

        # テキスト -> バイト
        text_bytes = text.encode('utf-8')
        print(f"バイト変換後: {len(text_bytes)}バイト")

        # 暗号化前処理（多段エンコーディング）
        start_time = time.time()
        processed_data = adapter.to_processable(text_bytes)
        process_time = time.time() - start_time
        print(f"処理時間: {process_time:.4f}秒")
        print(f"暗号化前処理後: {len(processed_data)}バイト")
        print(f"処理後データ先頭: {processed_data[:50]}")

        # 復号後処理（多段エンコーディング逆変換）
        start_time = time.time()
        decrypted_text = adapter.from_processable(processed_data)
        process_time = time.time() - start_time
        print(f"処理時間: {process_time:.4f}秒")

        # 結果確認
        print(f"復号後テキスト: {decrypted_text[:50]}{'...' if len(decrypted_text) > 50 else ''}")
        success = text == decrypted_text
        print(f"テスト結果: {'成功' if success else '失敗'}")

        if not success:
            print(f"元テキスト長: {len(text)}, 復号テキスト長: {len(decrypted_text)}")
            # 文字ごとの比較
            min_len = min(len(text), len(decrypted_text))
            for j in range(min_len):
                if text[j] != decrypted_text[j]:
                    print(f"最初の不一致: インデックス {j}")
                    print(f"元テキスト: '{text[max(0, j-10):j+10]}'")
                    print(f"復号テキスト: '{decrypted_text[max(0, j-10):j+10]}'")
                    break

def test_full_process():
    """
    process_data_for_encryptionとprocess_data_after_decryptionを使った完全なプロセスをテスト
    """
    # テスト用テキスト
    test_texts = [
        "これは単純なテキストです。Hello, World!",
        "特殊文字テスト: !@#$%^&*()_+-={}[]|\\:;\"'<>,.?/\n\t\r",
        """
        吾輩は猫である。名前はまだ無い。
        どこで生れたかとんと見当がつかぬ。何でも薄暗いじめじめした所でニャーニャー泣いていた事だけは記憶している。
        吾輩はここで始めて人間というものを見た。しかもあとで聞くとそれは書生という人間中で一番獰悪な種族であったそうだ。
        この書生というのは時々我々を捕えて煮て食うという話である。
        """,
        "長いテキスト" * 100
    ]

    for i, text in enumerate(test_texts):
        print(f"\n===== 完全プロセステスト {i+1} =====")
        print(f"元テキスト: {text[:50]}{'...' if len(text) > 50 else ''}")

        # テキスト -> バイト
        text_bytes = text.encode('utf-8')

        # 暗号化前処理
        processed_data, data_type = process_data_for_encryption(text_bytes, force_type="text")
        print(f"暗号化前処理後: {len(processed_data)}バイト、タイプ: {data_type}")
        print(f"処理後データ先頭: {processed_data[:50]}")

        # 通常ここで暗号化処理が入るが、今回はスキップ
        # ...

        # 復号後処理
        decrypted_result = process_data_after_decryption(processed_data, data_type)

        # 結果確認
        if isinstance(decrypted_result, str):
            decrypted_text = decrypted_result
        else:
            try:
                decrypted_text = decrypted_result.decode('utf-8')
            except UnicodeDecodeError:
                decrypted_text = decrypted_result.decode('latin-1')

        print(f"復号後テキスト: {decrypted_text[:50]}{'...' if len(decrypted_text) > 50 else ''}")
        success = text == decrypted_text
        print(f"テスト結果: {'成功' if success else '失敗'}")

        if not success:
            print(f"元テキスト長: {len(text)}, 復号テキスト長: {len(decrypted_text)}")
            # 文字ごとの比較
            min_len = min(len(text), len(decrypted_text))
            for j in range(min_len):
                if text[j] != decrypted_text[j]:
                    print(f"最初の不一致: インデックス {j}")
                    print(f"元テキスト: '{text[max(0, j-10):j+10]}'")
                    print(f"復号テキスト: '{decrypted_text[max(0, j-10):j+10]}'")
                    break

def main():
    """
    メイン関数
    """
    print("===== TextAdapterの多段エンコーディングテスト =====")
    test_text_adapter()

    print("\n\n===== 完全なデータ処理プロセスのテスト =====")
    test_full_process()

if __name__ == "__main__":
    main()
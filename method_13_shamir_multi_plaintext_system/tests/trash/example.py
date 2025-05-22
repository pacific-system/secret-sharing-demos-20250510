#!/usr/bin/env python3
"""
シャミア秘密分散法による複数平文復号システムの使用例

【責務】
このモジュールは、シャミア秘密分散法による複数平文復号システムの使用方法を
実際のコード例と実行フローで示す実行可能なデモスクリプトです。
以下の機能について段階的な使用例を提供します：
- システムの初期化
- パーティション別のパスワード設定
- 文書の暗号化と保存
- 複数ユーザーによる文書の追加
- 各パーティションでの復号操作
- 不正アクセスの検証
- セキュリティ自己診断の実行
"""

import os
import json
import sys
from pathlib import Path

# モジュールのパスを追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shamir.partition import initialize_system, PartitionManager
from shamir.crypto import encrypt_json_document, decrypt_json_document, save_encrypted_file, load_encrypted_file
from shamir.update import update_encrypted_document
from shamir.tests import security_self_diagnostic


def run_example():
    """シャミア秘密分散法システムの使用例を実行"""
    print("=== シャミア秘密分散法による複数平文復号システム：使用例 ===\n")

    # 作業ディレクトリを作成
    work_dir = Path("work_dir")
    work_dir.mkdir(exist_ok=True)

    # サンプルJSONファイルのパス
    sample_a_path = Path(__file__).parent / "sample_docs" / "a.json"
    sample_b_path = Path(__file__).parent / "sample_docs" / "b.json"

    if not sample_a_path.exists() or not sample_b_path.exists():
        print(f"エラー: サンプルファイルが見つかりません")
        print(f"  {sample_a_path} と {sample_b_path} を確認してください")
        return False

    try:
        # ステップ1: システムの初期化
        print("ステップ1: システムの初期化...")
        system_info = initialize_system()
        partition_a_key = system_info["partition_a_key"]
        partition_b_key = system_info["partition_b_key"]

        # 初期化情報を保存
        system_info_path = work_dir / "system_info.json"
        with open(system_info_path, 'w') as f:
            json.dump(system_info, f, indent=2)

        print(f"  システム情報を {system_info_path} に保存しました")
        print(f"  Aユーザー用パーティションマップキー: {partition_a_key[:10]}...")
        print(f"  Bユーザー用パーティションマップキー: {partition_b_key[:10]}...")

        # ステップ2: パスワードの設定
        print("\nステップ2: パスワードの設定...")
        password_a = "password_for_user_a"
        password_b = "password_for_user_b"
        print(f"  Aユーザーのパスワード: {password_a}")
        print(f"  Bユーザーのパスワード: {password_b}")

        # ステップ3: JSONファイルを読み込み
        print("\nステップ3: JSONファイルを読み込み...")
        with open(sample_a_path, 'r') as f:
            json_doc_a = json.load(f)
        with open(sample_b_path, 'r') as f:
            json_doc_b = json.load(f)

        print(f"  Aユーザーの文書タイトル: {json_doc_a['title']}")
        print(f"  Bユーザーの文書タイトル: {json_doc_b['title']}")

        # ステップ4: Aユーザーの文書を暗号化
        print("\nステップ4: Aユーザーの文書を暗号化...")
        encrypted_file_path = work_dir / "encrypted.json"

        encrypted_file = encrypt_json_document(
            json_doc_a,
            password_a,
            partition_a_key
        )

        # 暗号化ファイルを保存
        save_encrypted_file(encrypted_file, str(encrypted_file_path))
        print(f"  暗号化ファイルを {encrypted_file_path} に保存しました")

        # ステップ5: Bユーザーの文書を同じファイルに追加
        print("\nステップ5: Bユーザーの文書を同じファイルに追加（更新として）...")
        success, updated_file = update_encrypted_document(
            str(encrypted_file_path),
            json_doc_b,
            password_b,
            partition_b_key
        )

        if success:
            # 更新後のファイルを保存
            save_encrypted_file(updated_file, str(encrypted_file_path))
            print(f"  更新された暗号化ファイルを {encrypted_file_path} に保存しました")
        else:
            print(f"  エラー: 更新に失敗しました")
            return False

        # ステップ6: Aユーザーとして復号
        print("\nステップ6: Aユーザーとして復号...")
        loaded_file = load_encrypted_file(str(encrypted_file_path))

        decrypted_a = decrypt_json_document(
            loaded_file,
            partition_a_key,
            password_a
        )

        # 復号が成功したか確認
        if isinstance(decrypted_a, dict) and 'error' not in decrypted_a:
            print(f"  復号成功: {decrypted_a['title']}")
        else:
            print(f"  エラー: 復号に失敗しました - {decrypted_a.get('error')}")
            return False

        # ステップ7: Bユーザーとして復号
        print("\nステップ7: Bユーザーとして復号...")
        decrypted_b = decrypt_json_document(
            loaded_file,
            partition_b_key,
            password_b
        )

        # 復号が成功したか確認
        if isinstance(decrypted_b, dict) and 'error' not in decrypted_b:
            print(f"  復号成功: {decrypted_b['title']}")
        else:
            print(f"  エラー: 復号に失敗しました - {decrypted_b.get('error')}")
            return False

        # ステップ8: 異なるパスワードでの復号を試みる（失敗するはず）
        print("\nステップ8: 異なるパスワードでの復号を試みる...")
        wrong_decrypted = decrypt_json_document(
            loaded_file,
            partition_a_key,
            password_b
        )

        # 復号が失敗したか確認
        if isinstance(wrong_decrypted, dict) and 'error' in wrong_decrypted:
            print(f"  期待通り失敗: {wrong_decrypted['error']}")
        else:
            print(f"  エラー: 異なるパスワードでも復号できてしまいました")
            return False

        # ステップ9: セキュリティ自己診断を実行
        print("\nステップ9: セキュリティ自己診断を実行...")
        diagnostic_results = security_self_diagnostic(show_output=False)

        # 診断結果を保存
        diagnostic_path = work_dir / "security_diagnostic.json"
        with open(diagnostic_path, 'w') as f:
            json.dump(diagnostic_results, f, indent=2)

        print(f"  診断結果を {diagnostic_path} に保存しました")

        # 総合結果
        print("\n=== 実行結果 ===")
        if diagnostic_results["overall"]["success"]:
            print("✓ すべてのステップが正常に完了し、セキュリティ要件を満たしています")
        else:
            print("△ 機能テストは成功しましたが、一部のセキュリティ要件を満たしていません")
            print("  詳細は診断結果ファイルを確認してください")

        return True

    except Exception as e:
        print(f"エラー: 実行中に例外が発生しました - {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    run_example()
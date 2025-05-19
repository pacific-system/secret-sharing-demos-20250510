#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import argparse

def main():
    parser = argparse.ArgumentParser(description='暗号化ファイルからデータを抽出するシンプルなツール')
    parser.add_argument('encrypted_file', help='暗号化されたファイルパス')
    parser.add_argument('--output', help='出力ファイル名', default='extracted_data.json')
    args = parser.parse_args()

    # 暗号化ファイルの読み込み
    try:
        with open(args.encrypted_file, 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)
    except Exception as e:
        print(f"エラー: ファイルの読み込みに失敗しました - {e}")
        return

    # メタデータの抽出
    output_data = {
        'format': encrypted_data.get('format', '不明'),
        'version': encrypted_data.get('version', '不明'),
        'algorithm': encrypted_data.get('algorithm', '不明'),
        'true_filename': encrypted_data.get('true_filename', '不明'),
        'false_filename': encrypted_data.get('false_filename', '不明'),
        'true_data_type': encrypted_data.get('true_data_type', '不明'),
        'false_data_type': encrypted_data.get('false_data_type', '不明'),
        'true_size': encrypted_data.get('true_size', 0),
        'false_size': encrypted_data.get('false_size', 0),
        'true_original_size': encrypted_data.get('true_original_size', 0),
        'false_original_size': encrypted_data.get('false_original_size', 0),
        'chunk_size': encrypted_data.get('chunk_size', 0),
        'mask': encrypted_data.get('mask', {}),
        'true_chunks_count': len(encrypted_data.get('true_chunks', [])),
        'false_chunks_count': len(encrypted_data.get('false_chunks', [])),
        'metadata': encrypted_data.get('metadata', {})
    }

    # 出力ファイルに書き込み
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"抽出が完了しました: {args.output}")
    except Exception as e:
        print(f"エラー: 出力ファイルの書き込みに失敗しました - {e}")
        return

    # 結果の表示
    print("\n抽出されたデータ:")
    print(f"フォーマット: {output_data['format']}")
    print(f"バージョン: {output_data['version']}")
    print(f"アルゴリズム: {output_data['algorithm']}")
    print(f"\n真ファイル情報:")
    print(f"  ファイル名: {output_data['true_filename']}")
    print(f"  データタイプ: {output_data['true_data_type']}")
    print(f"  サイズ: {output_data['true_size']} バイト (元: {output_data['true_original_size']} バイト)")
    print(f"  チャンク数: {output_data['true_chunks_count']}")

    print(f"\n偽ファイル情報:")
    print(f"  ファイル名: {output_data['false_filename']}")
    print(f"  データタイプ: {output_data['false_data_type']}")
    print(f"  サイズ: {output_data['false_size']} バイト (元: {output_data['false_original_size']} バイト)")
    print(f"  チャンク数: {output_data['false_chunks_count']}")

    print(f"\nマスク関数情報:")
    print(f"  真マスク: {output_data['mask'].get('true_mask', {})}")
    print(f"  偽マスク: {output_data['mask'].get('false_mask', {})}")

if __name__ == "__main__":
    main()
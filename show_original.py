#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="オリジナルファイルの内容を表示")
    parser.add_argument("file_path", help="表示するファイルパス")
    parser.add_argument("--encoding", "-e", default="utf-8", help="エンコーディング (デフォルト: utf-8)")
    parser.add_argument("--binary", "-b", action="store_true", help="バイナリモードで表示")
    args = parser.parse_args()

    if not os.path.exists(args.file_path):
        print(f"エラー: ファイルが見つかりません: {args.file_path}")
        sys.exit(1)

    try:
        if args.binary:
            with open(args.file_path, "rb") as f:
                content = f.read()
                print(f"バイナリファイルサイズ: {len(content)} バイト")
                print(f"バイナリデータ (最初の100バイト): {content[:100]}")
                # HEX表示
                print("\nHEX表示 (最初の100バイト):")
                hex_content = content[:100].hex()
                for i in range(0, min(len(hex_content), 200), 2):
                    print(f"{hex_content[i:i+2]}", end=" ")
                    if (i+2) % 32 == 0:
                        print()
                print("\n")
        else:
            with open(args.file_path, "r", encoding=args.encoding) as f:
                content = f.read()
                print(f"テキストファイルサイズ: {len(content)} 文字")
                print(f"エンコーディング: {args.encoding}")
                print("\n内容:")
                print(content)
    except UnicodeDecodeError:
        print(f"エラー: ファイルを{args.encoding}でデコードできません。--binary オプションを使用するか、異なるエンコーディングを指定してください。")
        sys.exit(1)
    except Exception as e:
        print(f"エラー: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
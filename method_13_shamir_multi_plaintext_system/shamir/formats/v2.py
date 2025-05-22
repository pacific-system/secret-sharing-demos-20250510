"""
V2形式の暗号化ファイル形式モジュール

このモジュールでは、改良されたV2形式の暗号化ファイル形式を定義しています。
"""

class FileFormatV2:
    """
    V2形式の暗号化ファイル形式クラス

    V1形式よりも効率的で、headerとchunksのリストを使用する構造。
    チャンク単位でシェアを管理し、より効率的なデータ構造を提供します。
    """

    VERSION = 2

    @staticmethod
    def format_check(data):
        """
        V2形式かどうかをチェック

        Args:
            data: チェックするデータ

        Returns:
            True: V2形式の場合
            False: それ以外の場合
        """
        if not isinstance(data, dict):
            return False

        # V2形式はheaderとchunksを持つ
        if 'header' not in data or 'chunks' not in data:
            return False

        # ヘッダーを確認
        header = data['header']
        if not isinstance(header, dict):
            return False

        # 必須ヘッダーフィールドを確認
        required_fields = ['salt', 'threshold']
        for field in required_fields:
            if field not in header:
                return False

        # chunksはリストであること
        if not isinstance(data['chunks'], list):
            return False

        return True
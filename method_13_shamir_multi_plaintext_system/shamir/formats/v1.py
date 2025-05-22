"""
V1形式の暗号化ファイル形式モジュール

このモジュールでは、最も基本的なV1形式の暗号化ファイル形式を定義しています。
"""

class FileFormatV1:
    """
    V1形式の暗号化ファイル形式クラス

    基本的なJSONファイル形式で、メタデータとシェアのリストを含む単純な構造。
    """

    VERSION = 1

    @staticmethod
    def format_check(data):
        """
        V1形式かどうかをチェック

        Args:
            data: チェックするデータ

        Returns:
            True: V1形式の場合
            False: それ以外の場合
        """
        if not isinstance(data, dict):
            return False

        # V1形式はmetadataとsharesを持つ
        if 'metadata' not in data or 'shares' not in data:
            return False

        # メタデータを確認
        metadata = data['metadata']
        if not isinstance(metadata, dict):
            return False

        # 必須メタデータフィールドを確認
        required_fields = ['salt', 'total_chunks', 'threshold']
        for field in required_fields:
            if field not in metadata:
                return False

        # sharesはリストであること
        if not isinstance(data['shares'], list):
            return False

        return True
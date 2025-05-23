#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
パーティションマップキー長分析

【責務】
このモジュールは、生成されたパーティションマップキーの長さを分析し、
十分な長さであるかを検証します。

【依存関係】
- logging: ログ出力に使用
- statistics: 統計計算に使用

【使用方法】
from analysis.key_length_analyzer import KeyLengthAnalyzer

analyzer = KeyLengthAnalyzer()
results = analyzer.analyze(test_results)
"""

import logging
import statistics
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class KeyLengthAnalyzer:
    """パーティションマップキー長分析

    生成されたパーティションマップキーの長さを分析し、十分な長さであるかを検証する。
    """

    def __init__(self):
        """初期化処理"""
        self.name = "key_length"
        self.description = "パーティションマップキー長分析"
        self.min_expected_length = 500  # 最小期待長（実際のシステム値に基づいて設定する必要あり）
        logger.info(f"{self.description}モジュールを初期化しました")

    def analyze(self, test_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        パーティションマップキーの長さを分析する

        Args:
            test_results: テスト結果データ（テストID -> テスト結果の辞書）

        Returns:
            analysis_results: 分析結果
        """
        logger.info(f"{self.description}を実行します")

        analysis_results = {
            'name': self.name,
            'description': self.description,
            'keys_analyzed': [],
            'length_statistics': {},
            'pass': True  # デフォルトは合格
        }

        # 各テスト結果からパーティションマップキーを取得して分析
        for test_id, result in test_results.items():
            if not result.get('success', False):
                logger.warning(f"テスト {test_id} は失敗しているため、分析から除外します")
                continue

            if 'partition_map_key_a' in result and 'partition_map_key_b' in result:
                key_a = result['partition_map_key_a']
                key_b = result['partition_map_key_b']

                # キー長の検証
                key_a_length = len(key_a) if key_a else 0
                key_b_length = len(key_b) if key_b else 0

                # キー情報を記録
                key_info = {
                    'test_id': test_id,
                    'key_a_length': key_a_length,
                    'key_b_length': key_b_length,
                    'pass_a': key_a_length >= self.min_expected_length,
                    'pass_b': key_b_length >= self.min_expected_length
                }
                analysis_results['keys_analyzed'].append(key_info)

                # 最小期待長を満たしていない場合は不合格
                if key_a_length < self.min_expected_length or key_b_length < self.min_expected_length:
                    analysis_results['pass'] = False
                    logger.warning(f"テスト {test_id} のキー長が不十分です: A={key_a_length}, B={key_b_length}, 期待={self.min_expected_length}")
                else:
                    logger.info(f"テスト {test_id} のキー長は十分です: A={key_a_length}, B={key_b_length}, 期待={self.min_expected_length}")
            else:
                logger.warning(f"テスト {test_id} にパーティションマップキーが含まれていません")

        # 統計情報の計算
        if analysis_results['keys_analyzed']:
            lengths_a = [k['key_a_length'] for k in analysis_results['keys_analyzed']]
            lengths_b = [k['key_b_length'] for k in analysis_results['keys_analyzed']]

            try:
                analysis_results['length_statistics'] = {
                    'key_a': {
                        'min': min(lengths_a),
                        'max': max(lengths_a),
                        'avg': statistics.mean(lengths_a),
                        'median': statistics.median(lengths_a),
                        'stdev': statistics.stdev(lengths_a) if len(lengths_a) > 1 else 0
                    },
                    'key_b': {
                        'min': min(lengths_b),
                        'max': max(lengths_b),
                        'avg': statistics.mean(lengths_b),
                        'median': statistics.median(lengths_b),
                        'stdev': statistics.stdev(lengths_b) if len(lengths_b) > 1 else 0
                    }
                }

                logger.info(f"キー長統計情報: A={analysis_results['length_statistics']['key_a']}, B={analysis_results['length_statistics']['key_b']}")
            except Exception as e:
                logger.error(f"統計情報の計算中にエラーが発生しました: {str(e)}")
                analysis_results['error'] = str(e)
        else:
            logger.warning("分析可能なパーティションマップキーがありません")
            analysis_results['pass'] = False

        return analysis_results
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
パーティションMAP交差分析

【責務】
このモジュールは、テスト実行時に生成されたパーティションマップのインデックス値を分析し、
複数回のテスト実行間での一致率（%）を計算します。

【依存関係】
- logging: ログ出力に使用
- re: 正規表現による標準出力解析に使用

【使用方法】
from analysis.map_intersection_analyzer import MapIntersectionAnalyzer

analyzer = MapIntersectionAnalyzer()
results = analyzer.analyze(test_results)
"""

import logging
import re
import json
from typing import Dict, Any, List, Set, Tuple

logger = logging.getLogger(__name__)

class MapIntersectionAnalyzer:
    """パーティションMAP交差分析

    テスト実行間のパーティションマップインデックスの一致率を計算する。
    """

    def __init__(self):
        """初期化処理"""
        self.name = "map_intersection"
        self.description = "パーティションMAP交差分析"
        logger.info(f"{self.description}モジュールを初期化しました")

    def extract_partition_map(self, stdout: str, partition_type: str) -> List[int]:
        """
        標準出力からパーティションマップインデックスを抽出する

        Args:
            stdout: テスト実行時の標準出力
            partition_type: パーティションタイプ ('A' または 'B')

        Returns:
            マップインデックスのリスト、抽出に失敗した場合は空リスト
        """
        pattern = rf"{partition_type}領域パーティションMAP: (.+)(?:\n|$)"
        match = re.search(pattern, stdout)

        if match:
            map_str = match.group(1).strip()
            try:
                # JSON形式であるかチェック
                if map_str.startswith('[') and map_str.endswith(']'):
                    map_indices = json.loads(map_str)
                    return map_indices
                # カンマ区切りの数値リストの場合
                else:
                    # 角括弧を除去し、カンマで分割
                    map_str = map_str.strip('[]')
                    return [int(idx.strip()) for idx in map_str.split(',') if idx.strip().isdigit()]
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"{partition_type}領域パーティションMAPの解析に失敗しました: {e}")
                return []

        logger.warning(f"{partition_type}領域パーティションMAPが標準出力から見つかりませんでした")
        return []

    def calculate_intersection_rate(self, map1: List[int], map2: List[int]) -> float:
        """
        2つのマップ間の交差率（%）を計算する

        Args:
            map1: 1つ目のマップインデックスリスト
            map2: 2つ目のマップインデックスリスト

        Returns:
            交差率（%）
        """
        if not map1 or not map2:
            return 0.0

        # 集合に変換
        set1 = set(map1)
        set2 = set(map2)

        # 交差を計算
        intersection = set1.intersection(set2)

        # 交差率（全体要素数に対する割合）
        total_unique_elements = len(set1.union(set2))
        if total_unique_elements == 0:
            return 0.0

        return (len(intersection) / total_unique_elements) * 100.0

    def analyze_partition_maps(self, partition_maps: List[List[int]]) -> Dict[Tuple[int, int], float]:
        """
        複数のパーティションマップ間の交差率を計算する

        Args:
            partition_maps: パーティションマップのリスト（テスト実行回数分）

        Returns:
            交差率の辞書 {(map1_index, map2_index): 交差率}
        """
        result = {}

        # 各マップの組み合わせで交差率を計算
        for i in range(len(partition_maps)):
            for j in range(len(partition_maps)):
                if i != j:  # 同じマップ同士の比較は省略
                    map1 = partition_maps[i]
                    map2 = partition_maps[j]

                    # 交差率を計算
                    intersection_rate = self.calculate_intersection_rate(map1, map2)
                    result[(i+1, j+1)] = intersection_rate

        return result

    def analyze(self, test_results: Dict[str, Dict[str, Any]], all_test_results: List[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        テスト結果からパーティションマップの交差分析を行う

        Args:
            test_results: テスト結果データ（テストID -> テスト結果の辞書）
            all_test_results: 全テスト実行結果（複数回実行の場合）

        Returns:
            analysis_results: 分析結果
        """
        logger.info(f"{self.description}を実行します")

        analysis_results = {
            'name': self.name,
            'description': self.description,
            'pass': True,
            'a_map_intersection': {},
            'b_map_intersection': {},
            'a_b_map_intersection': {},
            'a_map_avg_rate': 0.0,
            'b_map_avg_rate': 0.0,
            'a_b_map_avg_rate': 0.0
        }

        # パーティションマップデータを収集
        a_maps = []
        b_maps = []

        # パーティションマップデータが保存されている場合は全テスト結果から抽出
        if all_test_results and len(all_test_results) > 0:
            for iteration_index, iteration_data in enumerate(all_test_results):
                iteration_number = iteration_index + 1
                logger.info(f"テスト結果から直接パーティションマップ情報を取得します: iteration={iteration_number}")

                # テスト結果からマップデータを抽出
                test_results_for_iter = iteration_data.get("results", {})

                # 各テスト結果からパーティションマップを抽出
                for test_id, test_result in test_results_for_iter.items():
                    if test_result.get("success", False):
                        # A領域のパーティションマップを抽出
                        if "partition_map_a" in test_result:
                            a_map = test_result["partition_map_a"]
                            if a_map and isinstance(a_map, list):
                                logger.info(f"A領域パーティションマップを取得しました: 要素数={len(a_map)}")
                                a_maps.append({"iteration": iteration_number, "map": a_map})

                        # B領域のパーティションマップを抽出
                        if "partition_map_b" in test_result:
                            b_map = test_result["partition_map_b"]
                            if b_map and isinstance(b_map, list):
                                logger.info(f"B領域パーティションマップを取得しました: 要素数={len(b_map)}")
                                b_maps.append({"iteration": iteration_number, "map": b_map})

        # 十分なデータが集まらなかった場合
        if len(a_maps) < 2 or len(b_maps) < 2:
            logger.warning("パーティションMAP交差分析に十分なパーティションマップが抽出できませんでした")
            analysis_results["pass"] = False
            return analysis_results

        # 全ての組み合わせについて交差率を計算（総当たり）
        # A領域パーティションマップ同士の交差
        for i, a_map_i in enumerate(a_maps):
            for j, a_map_j in enumerate(a_maps):
                if i != j:  # 同じマップ同士の比較は意味がないのでスキップ
                    # 交差率を計算
                    intersection_rate = self.calculate_intersection_rate(a_map_i["map"], a_map_j["map"])
                    # キーは (iteration_i, iteration_j) という形式
                    key = (a_map_i["iteration"], a_map_j["iteration"])
                    analysis_results["a_map_intersection"][key] = intersection_rate

        # B領域パーティションマップ同士の交差
        for i, b_map_i in enumerate(b_maps):
            for j, b_map_j in enumerate(b_maps):
                if i != j:  # 同じマップ同士の比較は意味がないのでスキップ
                    # 交差率を計算
                    intersection_rate = self.calculate_intersection_rate(b_map_i["map"], b_map_j["map"])
                    # キーは (iteration_i, iteration_j) という形式
                    key = (b_map_i["iteration"], b_map_j["iteration"])
                    analysis_results["b_map_intersection"][key] = intersection_rate

        # A領域とB領域のパーティションマップ間の交差
        for i, a_map in enumerate(a_maps):
            for j, b_map in enumerate(b_maps):
                # 交差率を計算
                intersection_rate = self.calculate_intersection_rate(a_map["map"], b_map["map"])
                # キーは (iteration_a, iteration_b) という形式
                key = (a_map["iteration"], b_map["iteration"])
                analysis_results["a_b_map_intersection"][key] = intersection_rate

        # 平均交差率を計算
        if analysis_results["a_map_intersection"]:
            a_map_rates = list(analysis_results["a_map_intersection"].values())
            analysis_results["a_map_avg_rate"] = sum(a_map_rates) / len(a_map_rates)
            logger.info(f"A領域パーティションマップの平均交差率: {analysis_results['a_map_avg_rate']:.2f}%")

        if analysis_results["b_map_intersection"]:
            b_map_rates = list(analysis_results["b_map_intersection"].values())
            analysis_results["b_map_avg_rate"] = sum(b_map_rates) / len(b_map_rates)
            logger.info(f"B領域パーティションマップの平均交差率: {analysis_results['b_map_avg_rate']:.2f}%")

        if analysis_results["a_b_map_intersection"]:
            ab_map_rates = list(analysis_results["a_b_map_intersection"].values())
            analysis_results["a_b_map_avg_rate"] = sum(ab_map_rates) / len(ab_map_rates)
            logger.info(f"A-B間パーティションマップの平均交差率: {analysis_results['a_b_map_avg_rate']:.2f}%")

        # 詳細ログ
        logger.info(f"交差分析のために抽出されたパーティションマップ: A={len(a_maps)}件, B={len(b_maps)}件")

        # 分析結果をより詳細に保存（テーブル用データ構造）
        # 各テスト実行ごとのマップキー比較結果を生成
        test_count = max(len(a_maps), len(b_maps))

        # A領域パーティションマップ交差テーブルを生成
        a_map_table = {}
        for i in range(1, test_count + 1):
            row_data = {}
            for j in range(1, test_count + 1):
                if i == j:
                    # 同一マップの交差率は100%（または'-'として表示）
                    row_data[j] = 100.0
                else:
                    # (i, j)のキーがあれば値を取得、なければデフォルト値
                    key = (i, j)
                    row_data[j] = analysis_results["a_map_intersection"].get(key, 0.0)
            a_map_table[i] = row_data
        analysis_results["a_map_table"] = a_map_table

        # B領域パーティションマップ交差テーブルを生成
        b_map_table = {}
        for i in range(1, test_count + 1):
            row_data = {}
            for j in range(1, test_count + 1):
                if i == j:
                    # 同一マップの交差率は100%（または'-'として表示）
                    row_data[j] = 100.0
                else:
                    # (i, j)のキーがあれば値を取得、なければデフォルト値
                    key = (i, j)
                    row_data[j] = analysis_results["b_map_intersection"].get(key, 0.0)
            b_map_table[i] = row_data
        analysis_results["b_map_table"] = b_map_table

        # A-B間パーティションマップ交差テーブルを生成
        ab_map_table = {}
        for i in range(1, test_count + 1):
            row_data = {}
            for j in range(1, test_count + 1):
                # (i, j)のキーがあれば値を取得、なければデフォルト値
                key = (i, j)
                row_data[j] = analysis_results["a_b_map_intersection"].get(key, 0.0)
            ab_map_table[i] = row_data
        analysis_results["ab_map_table"] = ab_map_table

        return analysis_results
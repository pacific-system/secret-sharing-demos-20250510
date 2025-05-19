#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

# シェアIDファイル読み込み
with open('shares.json', 'r') as f:
    shares = json.load(f)

# A文書用シェアIDセット
a_ids = shares['share_ids']['a']
with open('shares_a.json', 'w') as f:
    json.dump(a_ids, f)

# B文書用シェアIDセット
b_ids = shares['share_ids']['b']
with open('shares_b.json', 'w') as f:
    json.dump(b_ids, f)

print('シェアIDセットを抽出しました:')
print(f'A文書用: {len(a_ids)}個')
print(f'B文書用: {len(b_ids)}個')
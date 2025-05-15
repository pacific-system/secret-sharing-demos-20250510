#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の強化実装のテスト

このテストスクリプトは、準同型暗号マスキング方式の強化実装をテストします。
特に、識別不能性や攻撃耐性に関するテストを実施し、
設計要件通りに動作することを確認します。
"""

import os
import sys
import json
import base64
import binascii
import hashlib
import random
import math
import time
import argparse
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Union, cast

# モジュールのインポート
from method_8_homomorphic.homomorphic import (
    PaillierCrypto,
    derive_key_from_password
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)
from method_8_homomorphic.indistinguishable import (
    remove_comprehensive_indistinguishability_enhanced,
    analyze_key_type_enhanced,
    safe_log10
)
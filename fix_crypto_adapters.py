#!/usr/bin/env python3

with open('crypto_adapters.py', 'r') as f:
    content = f.read()

# Replace the problematic part
fixed_content = content.replace(
    'except UnicodeDecodeError:\n            # UTF-8u3067u30c7u30b3u30fcu30c9u3067u304du306au3044u5834u5408u306fu30d0u30a4u30cau30ea\n        return',
    'except UnicodeDecodeError:\n            # UTF-8u3067u30c7u30b3u30fcu30c9u3067u304du306au3044u5834u5408u306fu30d0u30a4u30cau30ea\n            return'
)

with open('crypto_adapters.py', 'w') as f:
    f.write(fixed_content)

print("Fixed indentation in crypto_adapters.py")
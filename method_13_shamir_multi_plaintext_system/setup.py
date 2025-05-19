from setuptools import setup, find_packages

setup(
    name="shamir-secret-sharing",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "gmpy2>=2.2.0",
        "cryptography>=45.0.0",
    ],
    python_requires=">=3.7",
    author="Shamir Secret Sharing Developer",
    author_email="example@example.com",
    description="Shamir Secret Sharing system with multiple plaintext decryption",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],
    entry_points={
        "console_scripts": [
            "shamir=shamir.app:main",
        ],
    },
)
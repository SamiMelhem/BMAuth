from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bmauth",
    version="0.1.0",
    author="Sami Melhem",
    author_email="SaMiLMelhem23@gmail.com",
    description="Biometric Authentication System for FastAPI applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/samimelhem/bmauth",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: FastAPI",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.68.0",
        "pydantic>=1.8.0",
        "cryptography>=3.4.0",
        "python-multipart>=0.0.5",
        "httpx>=0.24.0",
        "email-validator>=2.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
    },
)

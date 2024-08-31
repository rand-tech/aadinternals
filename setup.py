from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="aadinternals",
    version="0.1.0",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "aadinternals=aadinternals.cli:main",
        ],
    },
    author="rand0m",
    author_email="54098069+rand-tech@users.noreply.github.com",
    description="A Pythonic AADInternals recon tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rand-tech/aadinternals",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)

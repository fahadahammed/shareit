from setuptools import setup, find_packages

setup(
    name="shareit",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'psutil==7.0.0',
        'rich==14.0.0',
        'cryptography==50.0.2',
    ],
    entry_points={
        'console_scripts': [
            'shareit=shareit.cli:main',
        ],
    },
    author="Fahad Ahammed",
    description="A simple file sharing CLI tool.",
    license="MIT",
    python_requires=">=3.11,<4.0",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: 3.15",
    ],
)

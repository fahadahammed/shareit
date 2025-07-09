from setuptools import setup, find_packages

setup(
    name="shareit",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'psutil==7.0.0',
        'rich==14.0.0',
    ],
    entry_points={
        'console_scripts': [
            'shareit=shareit.cli:main',
        ],
    },
    author="Fahad Ahammed",
    description="A simple file sharing CLI tool.",
    license="MIT",
)

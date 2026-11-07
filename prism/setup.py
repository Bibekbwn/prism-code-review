from setuptools import setup, find_packages

setup(
    name='prism',
    version='1.0.0',
    description='Pre-Commit Code Review System - Multi-agent code review before push',
    packages=find_packages(),
    install_requires=[
        'google-generativeai==0.8.0',
    ],
    entry_points={
        'console_scripts': [
            'prism=prism.cli:main',
        ],
    },
    python_requires='>=3.9',
)
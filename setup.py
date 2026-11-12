from setuptools import setup, find_packages

setup(
    name='prism',
    version='2.0.0',
    description='Pre-Commit Code Review System - Multi-agent code review before push',
    packages=find_packages(include=['prism', 'prism.*']),
    package_data={
        'prism': ['dashboard.html', 'pre-commit-hook.sh'],
    },
    include_package_data=True,
    install_requires=[
        'google-generativeai>=0.8.0',
        'python-dotenv>=1.0.0',
    ],
    extras_require={
        'claude': ['anthropic>=0.30.0'],
        'openai': ['openai>=1.0.0'],
        'all': [
            'anthropic>=0.30.0',
            'openai>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'prism=prism.cli:main',
        ],
    },
    python_requires='>=3.9',
)
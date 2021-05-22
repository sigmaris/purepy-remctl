import os.path

from setuptools import setup

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='purepy-remctl',
    version='0.1.0',
    description='Pure Python implementation of the remctl protocol',
    author='Hugh Cole-Baker',
    author_email="hugh@sigmaris.info",
    url="https://github.com/sigmaris/purepy-remctl",
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        'gssapi>=1.2.0',
    ],
    extras_require={
        "dev": [
            "k5test ~= 0.9.2",
            "pytest ~= 6.2",
            "pytest-cov ~= 2.11.1",
        ],
    },
    py_modules=['purepy_remctl'],
)

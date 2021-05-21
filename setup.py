from setuptools import setup

setup(
    name='purepy-remctl',
    version='0.0.5',
    description='Pure Python implementation of the remctl protocol',
    author='Hugh Cole-Baker',
    author_email="hugh@sigmaris.info",
    url="https://github.com/sigmaris/purepy-remctl",
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

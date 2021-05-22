    from setuptools import setup

setup(
    name='purepy-remctl',
    version='0.0.4',
    description='Pure Python implementation of the remctl protocol',
    author='Hugh Cole-Baker',
    author_email="hugh@sigmaris.info",
    url="https://github.com/sigmaris/purepy-remctl",
    install_requires=[
        'python-gssapi>=0.4.1',
    ],
    py_modules=['purepy_remctl'],
)

from setuptools import setup, find_packages

setup(
    name='uaapp',

    version='0.0.1',

    description='UAA++: Utilities for UAA',

    url='https://github.com/cnelson/uaapp',

    author='Chris Nelson',
    author_email='cnelson@cnelson.org',

    license='Public Domain',

    packages=find_packages(),

    install_requires=[
        'gunicorn',
        'flask',
        'requests',
    ],

    test_suite='uaapp.tests',

    tests_require=[
        'blinker',
        'httmock',
        'mock'
    ]
)

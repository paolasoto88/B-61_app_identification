from setuptools import setup, find_packages

__author__ = 'Paola Soto'

setup(
    name = 'b-budget traffic classification',
    version = '0.0.1',
    packages=find_packages(),
    author='Paola Soto',
    author_email='paola.soto-arenas@uantwerpen.be',
    description='Traffic Classification package for b-budget projet',
    install_requires=['numpy>=1.14.1',
                      'matplotlib>=2.1.2',
                      'scikit-image>=0.14.0',
                      'dpkt',
                      'keras'],
    extras_require={"cpu": ['tensorflow==1.10.0'],
                    "gpu": ['tensorflow-gpu==1.10.0']},
    scripts=['bin/bbudget_preprocess.py',
             'bin/bbudget_down_sample.py']
)
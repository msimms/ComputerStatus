from setuptools import setup, find_packages

requirements = ['cherrypy', 'mako', 'bson', 'pymongo', 'bcrypt', 'markdown', 'unidecode']

setup(
    name='computerstatus',
    version='0.8.0',
    description='',
    url='https://github.com/msimms/ComputerStatus',
    author='Mike Simms',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=requirements,
)

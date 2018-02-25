from setuptools import setup, find_packages
import platform

target = platform.system()
requirements = ['psutil', 'pycron', 'requests']
if target == 'Windows':
    requirements.append('pypiwin32')
    requirements.append('wmi')

setup(
    name='computerstatus',
    version='0.1.0',
    description='A Python project for monitoring the health of a computer',
    url='https://github.com/msimms/ComputerStatus',
    author='Mike Simms',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=requirements,
)

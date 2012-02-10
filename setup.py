from setuptools import setup
from setuptools import find_packages

setup(
    name='gntauth',
    version='2.0.1',
    author='Kristoffer Snabb',
    url='https://github.com/geonition/django_auth',
    packages=find_packages(),
    include_package_data=True,
    package_data = {
        "gntauth": [
            "templates/*.js"
        ],
    },
    zip_safe=False,
    install_requires=['django']
)

from setuptools import setup
from setuptools import find_packages

setup(
    name='gntauth',
    version='4.0.x-alpha',
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

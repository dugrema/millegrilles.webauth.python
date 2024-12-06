from setuptools import setup, find_packages
from os import environ

__VERSION__ = environ.get('VBUILD') or '2024.0.0'

setup(
    name='millegrilles_webauth',
    version=__VERSION__,
    packages=find_packages(),
    url='https://github.com/dugrema/millegrilles.webauth.python',
    license='AFFERO',
    author='Mathieu Dugre',
    author_email='mathieu.dugre@mdugre.info',
    description="Serveur d'authentification usagers webauthn et x509 client pour MilleGrilles",
    install_requires=[]
)

from setuptools import setup, find_packages

setup(
    name='microschc',
    version='0.1',
    packages=find_packages(include=['microschc', 'microschc.*']),
    include_package_data=True,
    install_requires=[
        # Ajoutez ici les dépendances nécessaires, par exemple :
        # 'some_dependency>=1.0',
    ],
    package_data={
        'microschc': ['external/*.py', '/external/pktverify/*.py'],
    },
)

import setuptools
import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


requirements = read("requirements.txt").split()

setuptools.setup(
    name="mrextractor",
    version="0.0.1.dev3",
    author="Malware Revealer",
    author_email="revealer.malware@gmail.com",
    description="A library for binaries feature extraction",
    license="MIT",
    keywords="malware detection binary analysis feature extraction cyber security",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/malware-revealer/extractor",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)

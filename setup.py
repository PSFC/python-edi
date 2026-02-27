""" Setup script for PythonEDI

"""
from setuptools import setup, find_packages

setup(
    # name is now defined in pyproject.toml
    #name="PythonEDI",
    description="An X12 EDI generator/parser",
    long_description="""PythonEDI uses JSON format definitions to make it easy
    to generate or read X12 EDI messages from/to Python dicts/lists.""",
    url="https://github.com/glitchassassin/python-edi",
    author="Jon Winsley",
    author_email="jon.winsley@gmail.com",
    license="MIT",
    # version now set dynamically using setuptools_scm (via pyproject.toml)
    #version="0.2.2",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: Developers",
        "Intended Audience :: Healthcare Industry",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Topic :: Office/Business",
        "Topic :: Text Processing"
    ],
    keywords="x12 edi 810",
    packages=find_packages(exclude=['test']),
    package_data={"pythonedi": ["formats/*.json", "formats/codes/*.json"]},
    install_requires=['colorama'],
    include_package_data=True,
)

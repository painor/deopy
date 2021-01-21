import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
with open("requirements.txt", encoding="utf-8") as r:
    requires = [i.strip() for i in r]

setuptools.setup(
    name="deopy",
    version="0.0.5",
    author="painor",
    author_email="pi.oussama@gmail.com",
    description="A python library that helps you de-obfuscate/decrypt obfuscated python code",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/painor/deopy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requires,
)

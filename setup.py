import setuptools

setuptools.setup(
    name="solid_idp",
    version="0.0.1",
    author="Hamish Gibbs",
    author_email="Hamish.Gibbs@lshtm.ac.uk",
    description="Solid IdP.",
    url="https://github.com/hamishgibbs/solid_idp",
    install_requires=[
        'fastapi>=0.63.0',
        'pydantic>=1.7.3',
        'passlib>=1.7.4',
        'bcrypt>=3.2.0',
        'python-jose>=0.2.0',
        'python-multipart>=0.0.5',
        'rdflib>=5.0.0',
        'requests>=2.25.1',
        'Authlib>=0.15.3',
        'aiofiles>=0.6.0',
        'Jinja2>=2.11.3'
    ],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6"
)

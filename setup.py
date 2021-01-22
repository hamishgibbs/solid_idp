import setuptools

setuptools.setup(
    name="solid_idp",
    version="0.0.1",
    author="Hamish Gibbs",
    author_email="Hamish.Gibbs@lshtm.ac.uk",
    description="Solid IdP.",
    url="https://github.com/hamishgibbs/solid_idp",
    install_requires=[
        'fastapi',
        'pydantic',
        'passlib',
        'bcrypt'
    ],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6"
)

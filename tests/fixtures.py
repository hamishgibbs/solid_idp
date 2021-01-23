import pytest


@pytest.fixture(scope="session")
def tmpdir(tmpdir_factory):

    path = tmpdir_factory.mktemp("tmp")

    return str(path)

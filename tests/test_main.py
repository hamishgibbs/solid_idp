import pytest
from solid_idp import main
from passlib.context import CryptContext


def test_get_password_hash():

    res = main.get_password_hash('secret')

    assert res == 'secret'

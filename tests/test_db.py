import os
import pytest
from tests import fixtures
from solid_idp import db

tmpdir = fixtures.tmpdir


def test_init_db(tmpdir):

    db.init_db(tmpdir)

    assert os.path.exists(tmpdir + '/.db/oidc/users/users')


def test_create_user(tmpdir):

    db.create_user(
        username='test',
        hashed_password='secret',
        email='test@test.com',
        full_name='testy test',
        db=tmpdir + '/.db/oidc/users/users'
    )

    assert os.path.exists(tmpdir + '/.db/oidc/users/users/test.json')

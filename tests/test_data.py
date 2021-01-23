import os
from tests import fixtures
from solid_idp import data

tmpdir = fixtures.tmpdir


def test_init_user_data(tmpdir):

    data.init_user_data(tmpdir, 'test')
    print(os.listdir(tmpdir))

    assert os.path.exists(tmpdir + '/data/test/profile')


def test_create_personal_profile_document(tmpdir):

    data.create_personal_profile_document('test',
                                          tmpdir + '/data',
                                          iss='http://127.0.0.1:8000')

    assert os.path.exists(tmpdir + '/data/test/profile/card.ttl')

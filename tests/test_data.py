import os
from tests import fixtures
from solid_idp import data

tmpdir = fixtures.tmpdir


def test_init_user_data(tmpdir):

    data_dir = tmpdir + '/data'

    os.mkdir(data_dir)

    data.init_user_data(data_dir, 'test')

    assert os.path.exists(data_dir + '/test/profile')


def test_create_personal_profile_document(tmpdir):

    data.create_personal_profile_document('test',
                                          tmpdir + '/data',
                                          iss='http://127.0.0.1:8000')

    assert os.path.exists(tmpdir + '/data/test/profile/card.ttl')

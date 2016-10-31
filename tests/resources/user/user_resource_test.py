import json

import pytest

from user_api.models import User


@pytest.fixture
def create_valid_params():
    return {
        "name": "Joe Doe",
        "email": "joe_doe@email.com",
        "password": "unknown",
        "phones": [{
            "ddd": "21",
            "number": "00000000"
        }]
    }


@pytest.fixture
def create_invalid_params():
    return {
        "name": "John Doe",
        "email": "john_doe@email.com",
    }


def test_post_valid(api_test_client, create_valid_params):
    response = api_test_client.post('/api/users',
                                    data=json.dumps(create_valid_params),
                                    headers={"content-type": "application/json"})
    data = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    assert sorted(data.keys()) == ['created', 'email', 'id', 'last_login', 'name', 'phones', 'token']
    assert sorted(data['phones'][0]) == ['ddd', 'number']


def test_post_invalid(api_test_client, create_invalid_params):
    response = api_test_client.post('/api/users',
                                    data=json.dumps(create_invalid_params),
                                    headers={"content-type": "application/json"})
    data = json.loads(response.data.decode('utf-8'))
    assert data == {"mensagem": "password não pode ficar em branco"}
    assert response.status_code == 400


def test_post_invalid_existing_email(api_test_client, create_invalid_params, db):
    params = create_invalid_params
    user = User(**params)
    user.hash_password('farofa')
    db.session.add(user)
    db.session.commit()

    request_params = create_invalid_params
    request_params['password'] = 'farofa'
    response = api_test_client.post('/api/users',
                                    data=json.dumps(request_params),
                                    headers={"content-type": "application/json"})
    data = json.loads(response.data.decode('utf-8'))
    assert data == {"mensagem": "email já existente"}
    assert response.status_code == 400

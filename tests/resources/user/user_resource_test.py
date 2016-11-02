import copy

import json
import pytest

from user_api.auth import generate_jwt_token
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


@pytest.fixture
def expired_token():
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' + \
        'eyJleHAiOjE0Nzc5MzY3NDYsImlkZW50aXR5IjoyLCJuYmYiOjE0Nzc5MzY0NDYsImlhdCI6MTQ3NzkzNjQ0Nn0' + \
        '.zGMQyhJ25B7zHu9QoU_p2SlbfgDr0yRkTs_dQfpq6Q8'


@pytest.fixture
def user(session, create_invalid_params):
    params = create_invalid_params
    user = User(**params)
    user.hash_password('farofa')
    session.add(user)
    session.flush()
    user.token = generate_jwt_token(user).decode('utf-8')
    session.flush()
    return user


@pytest.fixture
def user_with_expired_token(session, expired_token):
    params = {
        "name": "Johnny Doe",
        "email": "johnny_doe@mail.com",
    }
    user = User(**params)
    user.hash_password('farofa')
    session.add(user)
    session.flush()
    user.token = expired_token
    session.flush()
    return user


def test_get_existent_user_with_token(api_test_client, user):
    response = api_test_client.get('/api/users/{}'.format(user.id),
                                   headers={"Authorization": "Bearer {}".format(user.token)})

    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 200
    assert data['id'] == user.id
    for key in ['created', 'email', 'last_login', 'name', 'phones', 'token']:
        assert data[key] is not None


def test_get_existent_user_without_token(api_test_client, user):
    response = api_test_client.get('/api/users/{}'.format(user.id))
    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 401
    assert data == {"mensagem": 'Não autorizado'}


def test_get_existent_user_expired_token(api_test_client, user_with_expired_token, expired_token):
    response = api_test_client.get('/api/users/{}'.format(user_with_expired_token.id),
                                   headers={"Authorization": "Bearer {}".format(expired_token)})
    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 419
    assert data == {"mensagem": 'Sessão inválida'}


@pytest.mark.skip()
def test_get_existent_user_refreshed_token(api_test_client, user, session):
    old_token = copy.deepcopy(user.token)
    api_test_client.post('/api/auth',
                         data=json.dumps({'email': user.email, 'password': 'farofa'}),
                         headers={"content-type": "application/json"})

    response = api_test_client.get('/api/users/{}'.format(user.id),
                                   headers={"Authorization": "Bearer {}".format(old_token)})
    data = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 401
    assert data == {"mensagem": 'Não autorizado'}

    User.query.filter_by(id=user.id).delete()
    session.commit()


def test_post_valid(api_test_client, create_valid_params):
    response = api_test_client.post('/api/users',
                                    data=json.dumps(create_valid_params),
                                    headers={"content-type": "application/json"})
    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 201
    for key in ['created', 'email', 'id', 'last_login', 'name', 'phones', 'token']:
        assert data[key] is not None
    assert sorted(data['phones'][0]) == ['ddd', 'number']


def test_post_invalid(api_test_client, create_invalid_params):
    response = api_test_client.post('/api/users',
                                    data=json.dumps(create_invalid_params),
                                    headers={"content-type": "application/json"})

    data = json.loads(response.data.decode('utf-8'))
    assert data == {"mensagem": "password não pode ficar em branco"}
    assert response.status_code == 400


def test_post_invalid_existent_email(api_test_client, create_invalid_params, user):
    request_params = create_invalid_params
    request_params['password'] = 'farofa'
    response = api_test_client.post('/api/users',
                                    data=json.dumps(request_params),
                                    headers={"content-type": "application/json"})

    data = json.loads(response.data.decode('utf-8'))
    assert data == {"mensagem": "email já existente"}
    assert response.status_code == 400

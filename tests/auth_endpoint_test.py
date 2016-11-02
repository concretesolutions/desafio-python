import json
import pytest

from user_api.models import User


@pytest.fixture
def valid_credentials():
    return {
        "email": "mark_doe@mail.com",
        "password": "doe_mark"
    }


@pytest.fixture
def email_not_found_credentials():
    return {
        "email": "carl_doe@mail.com",
        "password": "doe_mark"
    }


@pytest.fixture
def invalid_credentials():
    return {
        "email": "mark_doe@mail.com",
        "password": "doe_markk"
    }


@pytest.fixture
def user(session, valid_credentials):
    response = User(name='Mark Doe',
                    email=valid_credentials['email'])
    response.hash_password(valid_credentials['password'])
    session.add(response)
    session.flush()
    return response


def test_post_email_not_found(api_test_client, user, email_not_found_credentials):
    response = api_test_client.post('/api/auth',
                                    data=json.dumps(email_not_found_credentials),
                                    headers={"content-type": "application/json"})

    data = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 401
    assert data == {"mensagem": "Usuário e/ou senha inválidos"}


def test_post_invalid_credentials(api_test_client, user, invalid_credentials):
    response = api_test_client.post('/api/auth',
                                    data=json.dumps(invalid_credentials),
                                    headers={"content-type": "application/json"})
    data = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 401
    assert data == {"mensagem": "Usuário e/ou senha inválidos"}


def test_post_valid_credentials(api_test_client, user, valid_credentials):
    response = api_test_client.post('/api/auth',
                                    headers={"Content-Type": "application/json"},
                                    data=json.dumps(valid_credentials))

    data = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    for key in ['created', 'email', 'id', 'last_login', 'name', 'phones', 'token']:
        assert data[key] is not None

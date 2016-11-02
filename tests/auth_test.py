import json
import pytest

from user_api.models import User
from user_api.auth import (
    generate_auth_response,
    authenticate,
    load_identity,
    generate_jwt_token
)


@pytest.fixture
def token(user):
    return generate_jwt_token(user)


@pytest.fixture
def user(session):
    params = {"name": "Johnny Doe",
              "email": "johnny_doe@email.com"}
    instance = User(**params)
    instance.hash_password('farofa')
    session.add(instance)
    session.flush()
    return instance


def test_authenticate_valid_credentials(user):
    response = authenticate(user.email, 'farofa')
    assert response == user


def test_authenticate_invalid_credentials(user):
    response = authenticate(user.email, 'aaa')
    assert response is None


def test_load_identity_existing_user(api_test_client, user):
    response = load_identity({"identity": user.id})
    assert response == user


def test_load_identity_inexistent_user(api_test_client):
    response = load_identity({"identity": 0})
    assert response is None


def test_generate_auth_response(token, user):
    response = generate_auth_response(token, user)
    data = json.loads(response)
    for key in ['created', 'email', 'id', 'last_login', 'name', 'phones', 'token']:
        assert data[key] is not None

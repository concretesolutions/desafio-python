from os import environ
from datetime import timedelta

import pytest

from user_api.app import app as _app
from user_api import db as _db


def pytest_sessionstart(session):
    _app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('SQLALCHEMY_DATABASE_URI_TEST')
    _app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    _app.config['TESTING'] = True
    _app.config['SECRET_KEY'] = "super-secret"
    _app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=300)
    _db.drop_all()
    _db.create_all()


@pytest.fixture(scope="session")
def app(request):
    ctx = _app.app_context()
    ctx.push()

    def teardown():
        request.addfinalizer(teardown)
    return _app


@pytest.fixture(scope='session')
def db(app, request):
    def teardown():
        _db.drop_all()

    _db.app = app

    _db.create_all()

    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope='function')
def session(db, request):
    connection = db.engine.connect()
    transaction = connection.begin()

    session = db.create_scoped_session(options={"bind": connection, "binds": {}})
    db.session = session

    def teardown():
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


@pytest.fixture
def api_test_client(app):
    return app.test_client()

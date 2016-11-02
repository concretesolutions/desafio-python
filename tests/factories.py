import factory
from factory.alchemy import SQLAlchemyModelFactory

from user_api import db
from user_api.models import User


class UserFactory(SQLAlchemyModelFactory):
    class Meta:
        model = User
        sqlalchemy_session = db.Session

    id = factory.Sequence(lambda n: n)
    username = factory.Sequence(lambda n: 'User {}'.format(n))
    email = factory.Sequence(lambda n: 'email{}@mail.com'.format(n))

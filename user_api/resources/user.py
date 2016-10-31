from flask import current_app
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from webargs.flaskparser import FlaskParser

from user_api.resources.schemas import (
    UserRequestSchema,
    UserSchema
)
from user_api import db
from user_api.models import (
    User,
    Phone
)
from user_api.auth import generate_jwt_token


def error_handler(error):
    raise error

parser = FlaskParser(error_handler=error_handler)


class UserResource(Resource):

    @parser.use_kwargs(UserRequestSchema())
    def post(self, **kwargs):
        try:
            password = kwargs.pop('password')
            phones = kwargs.pop('phones')
            user = User(**kwargs)
            for phone in phones:
                params = phone
                params["user"] = user
                db.session.add(Phone(**params))
            user.hash_password(password)
            db.session.add(user)
            db.session.flush()
            user.token = generate_jwt_token(user)
            db.session.commit()
            return UserSchema().dump(user).data
        except IntegrityError as e:
            current_app.logger.error(e)
            db.session.rollback()
            raise e

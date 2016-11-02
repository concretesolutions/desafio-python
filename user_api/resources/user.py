from datetime import datetime

from flask import (
    current_app,
    request
)
from flask_jwt import jwt_required
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from webargs.flaskparser import use_kwargs

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


class UserResource(Resource):

    @jwt_required()
    def get(self, id):
        user = User.query.filter_by(id=id).first()
        token = request.headers.get('Authorization', '').\
            replace(current_app.config['JWT_AUTH_HEADER_PREFIX'], '').replace(' ', '')
        if user:
            if token and user.token != token:
                return {"mensagem": "Não autorizado"}, 401
            return UserSchema().dump(user).data, 200
        else:
            current_app.logger.warn('User with id {} not found'.format(id))
            return {"mensagem": "Usuário não encontrado"}, 404

    @use_kwargs(UserRequestSchema())
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
            user.token = generate_jwt_token(user).decode('utf-8')
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            return UserSchema().dump(user).data, 201
        except IntegrityError as err:
            db.session.rollback()
            current_app.logger.error(err)
            return {"mensagem": 'O usuário não pôde ser criado'}, 422

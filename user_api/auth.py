from datetime import datetime

from flask import current_app
from jwt import encode
from sqlalchemy.exc import IntegrityError

from user_api.models import User
from user_api import db
from user_api.resources.schemas import UserSchema


def generate_jwt_headers(identity):
    return None


def generate_jwt_payload(identity):
    iat = datetime.utcnow()
    exp = iat + current_app.config.get('JWT_EXPIRATION_DELTA')
    nbf = iat + current_app.config.get('JWT_NOT_BEFORE_DELTA')
    identity = getattr(identity, 'id') or identity['id']
    return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': identity}


def generate_jwt_token(identity):
    secret = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    required_claims = current_app.config['JWT_REQUIRED_CLAIMS']

    payload = generate_jwt_payload(identity)
    missing_claims = list(set(required_claims) - set(payload.keys()))

    if missing_claims:
        raise RuntimeError('Payload is missing required claims: %s' % ', '.join(missing_claims))

    headers = generate_jwt_headers(identity)

    return encode(payload, secret, algorithm=algorithm, headers=headers)


def generate_auth_response(access_token, identity):
    try:
        user = User.query.get(identity.id)
        user.token = access_token
        user.last_login_at = datetime.utcnow()
        db.session.add(user)
        db.session.commit()
    except IntegrityError as e:
        current_app.logger.error(e)
    return UserSchema().dump(user).data

from os import environ, getcwd
from os.path import join, exists
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api


dotenv_path = join(getcwd(), '.env')
if exists(dotenv_path):
    load_dotenv(dotenv_path)


def parse_boolean(value):
    return value in ['True', 'true']


user_api_app = Flask(__name__)


user_api_app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('SQLALCHEMY_DATABASE_URI')
user_api_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = parse_boolean(environ.get('SQLALCHEMY_TRACK_MODIFICATIONS'))
user_api_app.config['SECRET_KEY'] = environ.get('SECRET_KEY')
user_api_app.config['JWT_VERIFY'] = parse_boolean(environ.get('JWS_VERIFY'))
user_api_app.config['JWT_AUTH_HEADER_PREFIX'] = "Bearer"
user_api_app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=float(environ.get('EXPIRATION_DELTA', 300)))
user_api_app.config['JWT_AUTH_URL_RULE'] = "/api/auth"

db = SQLAlchemy(user_api_app)
api = Api(user_api_app, prefix="/api")

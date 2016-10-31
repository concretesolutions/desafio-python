from marshmallow import Schema, fields, validates, ValidationError

from user_api.models import User


ERROR_MESSAGES = {'null': 'não pode ser vazio',
                  'required': 'não pode ficar em branco',
                  'type': 'é inválido'}


def validate_uniqueness(field, value, klass):
    if klass.query.filter_by(**{field: value}).first():
        raise ValidationError('já existente')


class SelfSchema(Schema):
    def get_attribute(self, attr, obj, default):
        if attr == "self":
            return obj
        return super(SelfSchema, self).get_attribute(attr, obj, default)


class PhoneSchema(Schema):
    ddd = fields.String(required=True)
    number = fields.String(required=True)

    class Meta:
        strict = True


class BaseUserSchema(Schema):
    name = fields.String(required=True, error_messages=ERROR_MESSAGES)
    email = fields.Email(required=True, error_messages=ERROR_MESSAGES)
    phones = fields.Nested(PhoneSchema, many=True, required=True, error_messages=ERROR_MESSAGES)

    @validates('email')
    def validate_email(self, value):
        validate_uniqueness('email', value, User)

    class Meta:
        strict = True


class UserRequestSchema(BaseUserSchema):
    password = fields.String(required=True, error_messages=ERROR_MESSAGES)

    class Meta:
        strict = True


class UserSchema(BaseUserSchema):
    id = fields.Integer()
    created = fields.DateTime(attribute="created_at")
    modified = fields.DateTime(attribute="modified_at")
    last_login = fields.DateTime(attribute="last_login_at")
    token = fields.String()


class UserResponseSchema(Schema):
    users = fields.Nested(UserSchema)


class ErrorsSchema(SelfSchema):
    mensagem = fields.List(fields.String(), attribute="self")

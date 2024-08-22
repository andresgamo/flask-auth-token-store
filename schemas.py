from marshmallow import Schema, fields


class UserRegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
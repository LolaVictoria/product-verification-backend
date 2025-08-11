# schemas.py
from marshmallow import Schema, fields, validate

class SignupSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))
    role = fields.Str(validate=validate.OneOf(["developer", "manufacturer"]), load_default="developer")


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)

class ProductRegisterSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1))
    serial = fields.Str(required=True)
    blockchain_tx = fields.Str(load_default=None)

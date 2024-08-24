from marshmallow import Schema, fields, validates, ValidationError


class UserRegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class UploadFileSchema(Schema):
    username = fields.Str(required=True)
    file = fields.Raw(required=True)

    @validates("file")
    def validate_file(self, file):
        if not file.filename:
            raise ValidationError("No File provided")

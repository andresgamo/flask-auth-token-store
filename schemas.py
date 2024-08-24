from marshmallow import Schema, fields, validates, ValidationError


class UserRegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class UploadFileSchema(Schema):
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

    username = fields.Str(required=True)
    file = fields.Raw(required=True)

    @validates("file")
    def validate_file(self, file):
        filename = file.filename

        if not filename:
            raise ValidationError("No File provided")
        if (
            "." not in filename
            or filename.rsplit(".", 1)[1].lower() not in self.ALLOWED_EXTENSIONS
        ):
            raise ValidationError("File extension not supported")

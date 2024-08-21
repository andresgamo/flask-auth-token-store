import os
import logging
from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
from werkzeug.utils import secure_filename
import jwt
from flask_bcrypt import Bcrypt
from data_validation import DataValidation
from db_manager import DatabaseManager
from auth_middelware import token_required
from utility import serialize_document


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY")
app.config["SECRET_KEY"] = SECRET_KEY
api = Api(app)
bcrypt = Bcrypt(app)


class Upload(Resource):
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def _response(self, message, status_code, **kwargs):
        response = {"message": message}
        response.update(kwargs)
        return make_response(jsonify(response), status_code)

    def _generate_file_document(self, file):
        filename = secure_filename(file.filename)
        file_data = file.read()
        file_document = {
            "filename": filename,
            "file_data": file_data,
            "content_type": file.content_type,
        }
        return file_document

    @token_required
    def post(self):
        try:
            if not "file" in request.files and not "username" in request.form:
                return self._response("no file or username part", 400)

            current_user = request.form["username"]
            file = request.files["file"]

            if file.filename == "":
                return self._response("no file submitted", 400)

            if not self.allowed_file(file.filename):
                return self._response("File extension not supported", 400)

            file_document = self._generate_file_document(file)
            upload_id = self.db_manager.upload_file(file_document)

            if not upload_id:
                logger.error("Failed to upload file for user '%s'.", current_user)
                return self._response("File upload failed", 500)

            if self.db_manager.add_file_id(current_user, upload_id):
                logger.info(
                    "File '%s' successfully uploaded for user '%s'.",
                    file.filename,
                    current_user,
                )
                return self._response("Upload successful", 201)

            logger.error("Failed to add upload_id to user.")
            return self._response("Failed to add upload_id to user.", 500)

        except Exception as e:
            logger.error("Error: %s", e)
            return self._response("something went wrong", 500)

    @staticmethod
    def allowed_file(filename: str) -> bool:
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in Upload.ALLOWED_EXTENSIONS
        )


class UserLogin(Resource):
    def __init__(self, data_validation: DataValidation) -> None:
        self.data_validation = data_validation

    def _response(self, message, status_code, **kwargs):
        response = {"message": message}
        response.update(kwargs)
        return make_response(jsonify(response), status_code)

    def _generate_token(self, username) -> None:
        return jwt.encode(
            {"username": username}, app.config["SECRET_KEY"], algorithm="HS256"
        )

    def post(self):
        try:
            data = request.get_json()
            if not self.data_validation.data_complete(data):
                return self._response("missing user or password", 400)

            username = data.get("username")
            password = data.get("password")
            user = self.data_validation.check_login(username, password)

            if not user:
                return self._response("wrong username or password", 401)

            user["token"] = self._generate_token(username)

            user = serialize_document(user)

            return self._response("access granted", 200, user=user)

        except Exception as e:
            logger.error("Error: %s", e)
            return self._response("something went wrong", 500)


class UserRegister(Resource):
    def __init__(self, data_validation: DataValidation) -> None:
        self.data_validation = data_validation

    def _response(self, message, status_code, **kwargs):
        response = {"message": message}
        response.update(kwargs)
        return make_response(jsonify(response), status_code)

    def _hash_password(self, password):
        return self.data_validation.bcrypt.generate_password_hash(password).decode(
            "utf-8"
        )

    def post(self):
        try:
            data = request.get_json()
            if not self.data_validation.data_complete(data):
                return self._response("missing user or password", 400)
            username = data.get("username")
            password = data.get("password")
            if self.data_validation.db_manager.find_user_by_username(username):
                return self._response("User already exists", 409)

            hashed_password = self._hash_password(password)

            if self.data_validation.db_manager.insert_user(username, hashed_password):
                return self._response("User registered successfully", 201)
            return self._response("something went wrong", 500)

        except Exception as e:
            logger.error("Error: %s", e)
            return self._response("something went wrong", 500)


db_manager = DatabaseManager()
data_validation = DataValidation(db_manager, bcrypt)
api.add_resource(UserRegister, "/register", resource_class_args=(data_validation,))
api.add_resource(UserLogin, "/login", resource_class_args=(data_validation,))
api.add_resource(Upload, "/upload", resource_class_args=(db_manager,))


if "__main__" == __name__:
    app.run(host="0.0.0.0", port=8000)

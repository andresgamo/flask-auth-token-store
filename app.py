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

    @token_required
    def post(self):
        if "file" in request.files and "username" in request.form:
            current_user = request.form["username"]
            file = request.files["file"]
            if file.filename == "":
                return make_response(jsonify({"message": "no file submitted"}), 401)
            if self.allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_data = file.read()
                file_document = {
                    "filename": filename,
                    "file_data": file_data,
                    "content_type": file.content_type,
                }
                upload_id = db_manager.upload_file(file_document)
                if upload_id:
                    if db_manager.add_file_id(current_user, upload_id):
                        logger.info("Upload successfully")
                        return make_response(
                            jsonify({"message": "Upload successfully"}), 201
                        )
                    logger.error("User not found or upload_id could not be added.")
                    return make_response(
                        jsonify(
                            {
                                "message": "User not found or upload_id could not be added."
                            }
                        ),
                        401,
                    )
        return make_response(jsonify({"message": "no file part"}), 401)

    @staticmethod
    def allowed_file(filename: str) -> bool:
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in Upload.ALLOWED_EXTENSIONS
        )


class UserLogin(Resource):
    def __init__(self, data_validation: DataValidation) -> None:
        self.data_validation = data_validation

    def post(self):
        try:
            data = request.get_json()
            if self.data_validation.data_complete(data):
                username = data.get("username")
                password = data.get("password")
                user = self.data_validation.check_login(username, password)
                if user:
                    user["token"] = jwt.encode(
                        {"username": user["username"]},
                        app.config["SECRET_KEY"],
                        algorithm="HS256",
                    )
                    user = serialize_document(user)
                    return make_response(
                        jsonify({"message": "access granted", "user": user}), 200
                    )
                else:
                    return make_response(
                        jsonify({"message": "wrong username or password"}), 401
                    )
            else:
                return make_response(
                    jsonify({"message": "missing user or password"}), 400
                )
        except Exception as e:
            logger.error("Error: %s", e)
            return make_response(jsonify({"message": "something went wrong"}), 500)


class UserRegister(Resource):
    def __init__(self, data_validation: DataValidation) -> None:
        self.data_validation = data_validation

    def post(self):
        try:
            data = request.get_json()
            if self.data_validation.data_complete(data):
                username = data.get("username")
                password = data.get("password")
                if not self.data_validation.db_manager.find_user_by_username(username):
                    hashed_password = (
                        self.data_validation.bcrypt.generate_password_hash(
                            password
                        ).decode("utf-8")
                    )
                    if self.data_validation.db_manager.insert_user(
                        username, hashed_password
                    ):
                        return make_response(
                            jsonify({"message": "User registered successfully"}), 201
                        )

                    else:
                        return make_response(
                            jsonify({"message": "something went wrong"}), 500
                        )

                else:
                    return make_response(
                        jsonify({"message": "User already exists"}), 409
                    )

            else:
                return make_response(
                    jsonify({"message": "missing user or password"}), 400
                )

        except Exception as e:
            logger.error("Error: %s", e)
            return make_response(jsonify({"message": "something went wrong"}), 500)


db_manager = DatabaseManager()
data_validation = DataValidation(db_manager, bcrypt)
api.add_resource(UserRegister, "/register", resource_class_args=(data_validation,))
api.add_resource(UserLogin, "/login", resource_class_args=(data_validation,))
api.add_resource(Upload, "/upload", resource_class_args=(db_manager,))


if "__main__" == __name__:
    app.run(host="0.0.0.0", port=8000)

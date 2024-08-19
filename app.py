import os
import logging
from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
import jwt
from flask_bcrypt import Bcrypt
from data_validation import DataValidation
from db_manager import DatabaseManager


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY")
app.config["SECRET_KEY"] = SECRET_KEY
api = Api(app)
bcrypt = Bcrypt(app)


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


if "__main__" == __name__:
    app.run(host="0.0.0.0", port=8000)

from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
from pymongo import MongoClient
from flask_bcrypt import Bcrypt

app = Flask(__name__)
api = Api(app)
bcrypt = Bcrypt(app)


class DatabaseManager:
    def __init__(self) -> None:
        self.client = MongoClient("mongodb://mongo:27017")
        self.db = self.client["molidb"]
        self.users_collection = self.db["users"]

    def insert_user(self, username, hashed_password) -> bool:
        try:
            self.users_collection.insert_one(
                {"username": username, "password": hashed_password, "token": 10}
            )
            return True
        except Exception as e:
            print(f"Error inserting user: {e}")
            return False

    def find_user_by_username(self, username: str):
        return self.users_collection.find_one({"username": username})


class DataValidation:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def data_complete(self, data: dict) -> bool:
        """Validates user and password have been sent"""
        return bool(data.get("username")) and bool(data.get("password"))

    def user_exists(self, username: str) -> bool:
        """Verify in the db if user exist"""
        return bool(self.db_manager.find_user_by_username(username))

    def verify_password(self, username: str, password: str) -> bool:
        """Verify if the provided password matches the stored hash"""
        user = self.db_manager.find_user_by_username(username)
        if user:
            return bcrypt.check_password_hash(user.get('password'), password)
        return False

class UserRegister(Resource):
    def __init__(
        self, data_validation: DataValidation, db_manager: DatabaseManager
    ) -> None:
        self.data_validation = data_validation
        self.db_manager = db_manager

    def post(self):
        try:
            data = request.get_json()
            if self.data_validation.data_complete(data):
                username = data.get("username")
                password = data.get("password")
                if not self.data_validation.user_exists(username):
                    hashed_password = bcrypt.generate_password_hash(password).decode(
                        "utf-8"
                    )
                    if self.db_manager.insert_user(username, hashed_password):
                        return make_response(
                            jsonify({"message": "User registered successfully"}), 201
                        )

                    else:
                        return make_response(
                            jsonify({"message": "something went wrong"}), 500
                        )

                else:
                    return make_response(
                        jsonify({"message": "User already exist"}), 409
                    )

            else:
                return make_response(
                    jsonify({"message": "missing user or password"}), 400
                )

        except Exception:
            return make_response(jsonify({"message": "something went wrong"}), 500)


db_manager = DatabaseManager()
data_validation = DataValidation(db_manager)
api.add_resource(
    UserRegister, "/register", resource_class_args=(data_validation, db_manager)
)


if "__main__" == __name__:
    app.run(host="0.0.0.0", port=8000)

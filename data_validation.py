from typing import Union, Dict, Any
from flask_bcrypt import Bcrypt
from db_manager import DatabaseManager


class DataValidation:
    def __init__(self, db_manager: DatabaseManager, bcrypt: Bcrypt):
        self.db_manager = db_manager
        self.bcrypt = bcrypt

    def data_complete(self, data: dict) -> bool:
        """Validates user and password have been sent"""
        return bool(data.get("username")) and bool(data.get("password"))

    def verify_password(self, user, password: str) -> bool:
        """Verify if the provided password matches the stored hash"""
        return self.bcrypt.check_password_hash(user.get("password"), password)

    def check_login(self, username: str, password: str) -> Union[Dict[str, Any], bool]:
        user = self.db_manager.find_user_by_username(username)
        if user and self.verify_password(user, password):
            return user
        return False

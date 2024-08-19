import logging
from typing import Dict, Any
from pymongo import MongoClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
            logger.error("Error inserting user: %s", e)
            return False

    def find_user_by_username(self, username: str) -> Dict[str, Any]:
        return self.users_collection.find_one({"username": username})

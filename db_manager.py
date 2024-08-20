import logging
from typing import Dict, Any, Union
from pymongo import MongoClient
from dependency_resolver import DependencyResolver

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
            cls._instance._initialize()
        return cls._instance

    def __init__(self):
        if not hasattr(self, "initialized"):
            self.client = MongoClient("mongodb://mongo:27017")
            self.db = self.client["molidb"]
            self.users_collection = self.db["users"]
            self.uploads_collection = self.db["uploads"]
            self.initialized = True

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

    def upload_file(self, file_document: dict) -> Union[str, None]:
        upload_id = self.uploads_collection.insert_one(file_document).inserted_id
        return str(upload_id)

    def add_file_id(self, current_user: str, upload_id: str) -> Union[str, None]:
        try:
            result = self.users_collection.update_one(
                {"username": current_user}, {"$push": {"uploads": upload_id}}
            )
            if result.modified_count > 0:
                return upload_id
            return None
        except Exception as e:
            logger.error("Error uploading file: %s", e)


DependencyResolver.register("db_manager", DatabaseManager())

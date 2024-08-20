import logging
from functools import wraps
from flask import current_app, request, make_response, jsonify
import jwt
from dependency_resolver import DependencyResolver as DR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return make_response(
                jsonify(
                    {
                        "message": "Invalid Authentication token!",
                        "data": None,
                        "error": "Unauthorized",
                    },
                    401,
                )
            )
        try:
            data = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithm="HS256"
            )
            current_user = DR.get("db_manager").find_user_by_username(data["username"])
            if current_user:
                return func(*args, **kwargs)
            return make_response(
                jsonify(
                    {
                        "message": "Invalid Authentication token!",
                        "data": None,
                        "error": "Unauthorized",
                    },
                    401,
                )
            )
        except Exception as e:
            logger.error("%s", e)
            return make_response(
                jsonify(
                    {"message": "Something went wrong", "data": None, "error": str(e)},
                ),
                500,
            )

    return wrapper

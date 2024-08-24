import logging
from functools import wraps
from flask import current_app, request, make_response, jsonify
import jwt
from dependency_resolver import DependencyResolver as DR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def response(message, status_code, **kwargs):
    response = {"message": message}
    response.update(kwargs)
    return make_response(jsonify(response), status_code)


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return response(
                "Invalid Authentication token!", 401, data=None, error="Unauthorized"
            )
        try:
            data = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithms="HS256"
            )
            current_user = DR.get("db_manager").find_user_by_username(data["username"])
            if not current_user:
                return response(
                    "Invalid Authentication token!",
                    401,
                    data=None,
                    error="Unauthorized",
                )
            return func(*args, **kwargs)
        except Exception as e:
            logger.error("%s", e)
            return response("Something went wrong", 500, data=None, error=str(e))

    return wrapper

#!/usr/bin/env python3

from flask_jwt_extended import get_jwt_identity
from functools import wraps

# custom imports
from app import mongo


def user_is(role):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            email = get_jwt_identity()
            user = mongo.db.users.find_one({'email': email})

            if not user:
                return {'message': 'You are not authenticated'}, 401

            if 'roles' not in user:
                return {'message': 'You have no roles ask for support'}, 400

            if role in user['roles']:
                return func(*args, **kwargs)

            return {'message': 'You do not have access'}, 403
        return inner
    return wrapper

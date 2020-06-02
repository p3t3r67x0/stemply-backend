#!/usr/bin/env python3

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail

from jwt.exceptions import ExpiredSignatureError
from pymongo.errors import ServerSelectionTimeoutError
from werkzeug.exceptions import (NotFound, BadRequest, BadGateway,
                                 MethodNotAllowed, RequestEntityTooLarge,
                                 InternalServerError)


errors = {
    'TypeError': {
        'status': 500,
        'message': 'Something went wrong application error'
    },
    'NotFound': {
        'status': 404,
        'message': 'Requested resource was not found on server'
    },
    'BadRequest': {
        'status': 400,
        'message': 'Bad request the error has been reported'
    },
    'BadGateway': {
        'status': 502,
        'message': 'Bad gateway application is not reachable'
    },
    'MethodNotAllowed': {
        'status': 405,
        'message': 'The method is not allowed for resource'
    },
    'InternalServerError': {
        'status': 500,
        'message': 'Something went wrong internal server error'
    },
    'RequestEntityTooLarge': {
        'status': 413,
        'message': 'File transmitted exceeds the capacity limit'
    },
    'ServerSelectionTimeoutError': {
        'status': 500,
        'message': 'Something went wrong application error'
    },
    'ExpiredSignatureError': {
        'status': 401,
        'message': 'Token signature has expired'
    }
}


app = Flask(__name__, static_folder=None)
app.config.from_json('config.json')
api = Api(app, errors=errors, prefix='/api/v1')
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
mail = Mail(app)
cors = CORS(app)


@jwt.unauthorized_loader
def custom_unauthorized(self):
    return jsonify(message=self), 401


@jwt.invalid_token_loader
def custom_invalid_token(self):
    return jsonify(message=self), 422


@jwt.expired_token_loader
def custom_expired_token(expired_token):
    token_type = expired_token['type']

    return jsonify({
        'message': 'The {} token has expired'.format(token_type)
    }), 401

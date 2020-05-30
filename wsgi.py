#!/usr/bin/env python3

import ast
import json

from flask import Flask, jsonify, request
from flask_restful import Api, Resource, reqparse
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_json('config.json')
api = Api(app, prefix='/api/v1')
bcrypt = Bcrypt(app)
mongo = PyMongo(app)


class Endpoint(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('username',
                                   type=str,
                                   required=True,
                                   help='No valid username provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('password',
                                   type=str,
                                   required=True,
                                   help='No valid password provided',
                                   location='json',
                                   nullable=False)

        super(Endpoint, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        username = args.username
        password = bcrypt.generate_password_hash(args.password)

        mongo.db.users.insert_one({'username': username, 'password': password})


api.add_resource(Endpoint, '/')


if __name__ == '__main__':
    app.run(debug=True)

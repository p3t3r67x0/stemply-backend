#!/usr/bin/env python3

from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config.from_json('config.json')
api = Api(app, prefix='/api/v1')
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

        if args.password:
            users = mongo.db.users.find({'online': True})
            # user = mongo.db.users.find({'_id': username})

            return jsonify({'users': users})


api.add_resource(Endpoint, '/')


if __name__ == '__main__':
    app.run(debug=True)

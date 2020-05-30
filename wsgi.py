#!/usr/bin/env python3

import requests as r

from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import (JWTManager, create_access_token,
                                create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity)
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

from bson.objectid import ObjectId


app = Flask(__name__)
app.config.from_json('config.json')
api = Api(app, prefix='/api/v1')
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

wpapi = 'https://zackig.sbicego.ch/wp-json/wp/v2/'


class UserSignup(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('email',
                                   type=str,
                                   required=True,
                                   help='No valid email provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('password',
                                   type=str,
                                   required=True,
                                   help='No valid password provided',
                                   location='json',
                                   nullable=False)

        super(UserSignup, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        email = args.email
        password = bcrypt.generate_password_hash(args.password)

        try:
            mongo.db.users.insert_one(
                {'email': email, 'password': password})
            refresh_token = create_refresh_token(identity=email)
            access_token = create_access_token(identity=email)

            return {
                'message': 'User {} was created'.format(email),
                'refresh_token': refresh_token,
                'access_token': access_token
            }
        except Exception:
            return {'message': 'Something went wrong'}, 500


class UserSignin(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('email',
                                   type=str,
                                   required=True,
                                   help='No valid email provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('password',
                                   type=str,
                                   required=True,
                                   help='No valid password provided',
                                   location='json',
                                   nullable=False)

        super(UserSignin, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        email = args.email
        password = args.password

        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            refresh_token = create_refresh_token(identity=email)
            access_token = create_access_token(identity=email)

            return {
                'message': 'Logged in as {}'.format(email),
                'refresh_token': refresh_token,
                'access_token': access_token
            }
        else:
            return {'message': 'Wrong credentials'}


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)

        return {'access_token': access_token}


class Challange(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('id',
                                   type=str,
                                   required=False,
                                   help='No valid id provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('title',
                                   type=str,
                                   required=False,
                                   help='No valid title provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('content',
                                   type=str,
                                   required=False,
                                   help='No valid content provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('duration',
                                   type=str,
                                   required=False,
                                   help='No valid duration provided',
                                   location='json',
                                   nullable=False)

        super(Challange, self).__init__()

    @jwt_required
    def get(self):
        response = []

        for data in mongo.db.challenge.find():
            d = {}

            for k, v in data.items():
                if isinstance(v, ObjectId):
                    d[k] = str(v)
                else:
                    d[k] = v

            response.append(d)

        return {'message': response}

    @jwt_required
    def post(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            mongo.db.challenge.insert_one(
                {'title': title, 'content': content, 'duration': duration})

            return {'message': 'Challenge was successfully added'}
        except Exception:
            return {'message': 'Something went wrong'}, 500

    @jwt_required
    def put(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            condition = {'_id': id}
            statement = {'title': title,
                         'content': content, 'duration': duration}

            data = mongo.db.challenge.update_one(condition, statement)

            return {'message': 'Challenge {} was added'.format(data.id)}
        except Exception:
            return {'message': 'Something went wrong'}, 500


class Fetch(Resource):
    def get(self):
        posts = r.get(wpapi+'posts').json()
        return {
            'length': len(posts),
            'data': posts
        }


api.add_resource(UserSignin, '/signin')
api.add_resource(UserSignup, '/signup')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(Challange, '/challenge', endpoint='create')
api.add_resource(Fetch, '/fetch')


if __name__ == '__main__':
    app.run(debug=True)

#!/usr/bin/env python3

from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import (JWTManager, create_access_token,
                                create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity)
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

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

        super(UserSignup, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        username = args.username
        password = bcrypt.generate_password_hash(args.password)

        try:
            mongo.db.users.insert_one(
                {'username': username, 'password': password})
            refresh_token = create_refresh_token(identity=username)
            access_token = create_access_token(identity=username)

            return {
                'message': 'User {} was created'.format(username),
                'refresh_token': refresh_token,
                'access_token': access_token
            }
        except Exception:
            return {'message': 'Something went wrong'}, 500


class UserSignin(Resource):
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

        super(UserSignin, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        username = args.username
        password = args.password

        user = mongo.db.users.find_one({'username': username})

        if user and bcrypt.check_password_hash(user['password'], password):
            refresh_token = create_refresh_token(identity=username)
            access_token = create_access_token(identity=username)

            return {
                'message': 'Logged in as {}'.format(username),
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


class ChallangesEndpoint(Resource):
    @jwt_required
    def get(self):
        return {'message': 'here will be the api endpoint'}

    @jwt_required
    def post(self):
        return {'message': 'here will be the api endpoint'}


api.add_resource(UserSignin, '/signin')
api.add_resource(UserSignup, '/signup')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(ChallangesEndpoint, '/challenges')


if __name__ == '__main__':
    app.run(debug=True)

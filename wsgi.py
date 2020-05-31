#!/usr/bin/env python3

import re
import requests as r

from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import (JWTManager, create_access_token,
                                create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity)
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from durations import Duration
from bson.objectid import ObjectId
from flask_cors import CORS

app = Flask(__name__)
app.config.from_json('config.json')
api = Api(app, prefix='/api/v1')
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
cors = CORS(app)

wpapi = 'https://zackig.sbicego.ch/wp-json/wp/v2/'


def cleantext(text):
    return re.sub(re.compile('<.*?>'), '', text.replace('\n', '').replace('\r', ''))


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
            data = mongo.db.users.insert_one(
                {'email': email, 'password': password})
            refresh_token = create_refresh_token(identity=email)
            access_token = create_access_token(identity=email)

            return {
                'message': 'User {} was created'.format(email),
                'refresh_token': refresh_token,
                'access_token': access_token,
                'user_id': str(data.inserted_id)
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
                'access_token': access_token,
                'user_id': str(user['_id'])
            }
        else:
            return {'message': 'Wrong credentials'}


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)

        return {'access_token': access_token}


class Challenge(Resource):
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

        super(Challenge, self).__init__()

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
                {'title': title, 'content': content,
                 'duration': duration, 'editedinwebapp': True})

            return {'message': 'Challenge was successfully added'}
        except Exception:
            return {'message': 'Something went wrong'}, 500


class ChallengeDetail(Resource):
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

        super(ChallengeDetail, self).__init__()

    @jwt_required
    def post(self):
        args = self.reqparse.parse_args()

        if not args.id:
            return {'message': 'No valid id provided'}, 404

        response = []

        data = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})
        print(args.id)

        if data:
            d = {}

            for k, v in data.items():
                if isinstance(v, ObjectId):
                    d[k] = str(v)
                else:
                    d[k] = v

            response.append(d)

        return {'message': response}

    @jwt_required
    def put(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            statement = {'title': title,
                         'content': content,
                         'duration': duration,
                         'editedinwebapp': True
                         }

            data = mongo.db.challenge.update_one(
                {'_id': ObjectId(args.id)}, {'$set': statement}, upsert=True)

            if data.modified_count > 0:
                return {'message': 'Challenge was successfully updated'}
            else:
                return {'message': 'Nothing to update already uptodate'}
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong'}, 500


class ChallengeUser(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('challenge_id',
                                   type=str,
                                   required=False,
                                   help='No valid challenge id provided',
                                   location='json',
                                   nullable=False)

        super(ChallengeUser, self).__init__()

    @jwt_required
    def put(self):
        email = get_jwt_identity()
        args = self.reqparse.parse_args()

        challenge_id = args.challenge_id

        statement = {'challenge_id': challenge_id}

        user = mongo.db.challenge.update_one(
            {'email': email}, {'$addToSet': statement}, upsert=True)

        print(user.modified_count)

        if user.modified_count > 0:
            return {'message': 'User subscribed to challenge'}
        else:
            return {'message': 'Nothing to update already uptodate'}


class Fetch(Resource):
    def get(self):
        i = 0
        j = 0
        posts = r.get(wpapi + 'posts').json()
        for post in posts:
            challenge = mongo.db.challenge.find_one({'wpid': post['id']})
            try:
                duration = int(Duration(
                    r.get(wpapi + 'tags?post=' +
                          str(post['id'])).json()[0]['name']
                ).to_seconds())
            except Exception:
                duration = 604800  # default duration 1 week

            if not challenge:
                try:
                    mongo.db.challenge.insert_one({
                        'wpid': post['id'],
                        'date': post['date'],
                        'modified': post['modified'],
                        'title': post['title']['rendered'],
                        'content': cleantext(post['content']['rendered']),
                        'duration': duration,
                        'editedinwebapp': False
                    })
                    i += 1
                except Exception:
                    pass

            else:
                try:
                    if not challenge['editedinwebapp']:
                        data = {
                            'wpid': post['id'],
                            'date': post['date'],
                            'modified': post['modified'],
                            'title': post['title']['rendered'],
                            'content': cleantext(post['content']['rendered']),
                            'duration': duration
                        }
                        mongo.db.challenge.update_one(
                            {'_id': challenge['_id']},
                            {"$set": data}
                        )
                        j += 1
                except Exception:
                    pass

        return {'added': i, 'updated': j}


api.add_resource(UserSignin, '/signin')
api.add_resource(UserSignup, '/signup')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(Challenge, '/challenge')
api.add_resource(ChallengeUser, '/challenge/user')
api.add_resource(ChallengeDetail, '/challenge/detail')
api.add_resource(Fetch, '/fetch')


if __name__ == '__main__':
    app.run(debug=True)

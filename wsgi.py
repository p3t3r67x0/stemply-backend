#!/usr/bin/env python3

import re
import pytz
import requests as r

from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import (JWTManager, create_access_token,
                                create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity)
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_cors import CORS

from bson.objectid import ObjectId
from durations import Duration
from datetime import datetime
from functools import wraps


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
                {'email': email, 'password': password, 'roles': ['user']})

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
    @user_is('user')
    def get(self):
        array = []

        for data in mongo.db.challenge.find():
            d = {}

            for k, v in data.items():
                if isinstance(v, ObjectId):
                    d[k] = str(v)
                elif isinstance(v, datetime):
                    d[k] = str(v)
                else:
                    d[k] = v

            array.append(d)

        return {'message': array}

    @jwt_required
    @user_is('admin')
    def post(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            mongo.db.challenge.insert_one(
                {'title': title, 'content': content,
                 'duration': duration, 'created': datetime.utcnow(),
                 'modified': datetime.utcnow()})

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
    @user_is('admin')
    def post(self):
        args = self.reqparse.parse_args()

        if not args.id:
            return {'message': 'No valid id provided'}, 404

        array = []

        data = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})
        print(args.id)

        if data:
            d = {}

            for k, v in data.items():
                if isinstance(v, ObjectId):
                    d[k] = str(v)
                elif isinstance(v, datetime):
                    d[k] = str(v)
                else:
                    d[k] = v

            array.append(d)

        return {'message': array}

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            statement = {'title': title,
                         'content': content,
                         'duration': duration,
                         'modified': datetime.utcnow()
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

        self.reqparse.add_argument('id',
                                   type=str,
                                   required=False,
                                   help='No valid challenge id provided',
                                   location='json',
                                   nullable=False)

        super(ChallengeUser, self).__init__()

    @jwt_required
    @user_is('user')
    def get(self):
        results = []
        email = get_jwt_identity()

        user = mongo.db.users.find_one({'email': email})

        if not user:
            return {'message': 'User data was not found'}

        if 'challenges' in user:
            results = mongo.db.challenge.find(
                {'_id': {'$in': [ObjectId(id) for id in user['challenges']]}})

        array = []

        for data in results:
            d = {}

            for k, v in data.items():
                if isinstance(v, ObjectId):
                    d[k] = str(v)
                elif isinstance(v, datetime):
                    d[k] = str(v)
                else:
                    d[k] = v

            array.append(d)

        return {'message': array}

    @jwt_required
    @user_is('admin')
    def put(self):
        email = get_jwt_identity()
        args = self.reqparse.parse_args()

        id = args.id

        if not id:
            return {'message': 'Challenge id missing'}

        query = {'email': email, 'challenges': {'$in': [id]}}

        data = mongo.db.users.find_one(query)
        statement = {'challenges': id}

        if data:
            user = mongo.db.users.update_one(
                {'email': email}, {'$pull': statement}, upsert=True)

            if user.modified_count > 0:
                return {'message': 'User unsubscribed from challenge'}
            else:
                return {'message': 'Nothing to update already uptodate'}

        user = mongo.db.users.update_one(
            {'email': email}, {'$addToSet': statement}, upsert=True)

        if user.modified_count > 0:
            return {'message': 'User subscribed to challenge'}
        else:
            return {'message': 'Nothing to update already uptodate'}


class Fetch(Resource):
    @jwt_required
    @user_is('admin')
    def get(self):
        i = 0
        j = 0

        posts = r.get(wpapi + 'posts').json()
        timezone = pytz.timezone('Europe/Zurich')

        for post in posts:
            challenge = mongo.db.challenge.find_one({'wpid': post['id']})

            created = timezone.localize(datetime.strptime(
                post['date'], '%Y-%m-%dT%H:%M:%S'))
            modified = timezone.localize(datetime.strptime(
                post['modified'], '%Y-%m-%dT%H:%M:%S'))

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
                        'created': created,
                        'modified': modified,
                        'title': post['title']['rendered'],
                        'content': cleantext(post['content']['rendered']),
                        'duration': duration,
                    })
                    i += 1
                except Exception:
                    pass

            else:
                try:
                    if modified > pytz.utc.localize(challenge['modified']):
                        print('Updating from WP....')

                        data = {
                            'wpid': post['id'],
                            'created': created,
                            'modified': modified,
                            'title': post['title']['rendered'],
                            'content': cleantext(post['content']['rendered']),
                            'duration': duration
                        }

                        mongo.db.challenge.update_one(
                            {'_id': challenge['_id']}, {'$set': data})

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

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

from pymongo.cursor import Cursor
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


def analyze(o):
    d = {}

    for k, v in o.items():
        if isinstance(v, ObjectId):
            d[k] = str(v)
        elif isinstance(v, datetime):
            d[k] = str(v)
        elif isinstance(v, bytes):
            d[k] = str(v)
        else:
            d[k] = v

    return d


def normalize(objects):
    if isinstance(objects, list) or isinstance(objects, Cursor):
        array = []

        for object in objects:
            array.append(analyze(object))

        return array
    elif isinstance(objects, dict):
        return analyze(objects)


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
                'user_roles': user['roles'],
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
        data = mongo.db.challenge.find()

        if not data:
            return {'message': 'No chalenges was found ask for support'}

        return {'message': normalize(data)}

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
                 'duration': duration, 'created': datetime.utcnow()})

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
    @user_is('user')
    def post(self):
        args = self.reqparse.parse_args()

        data = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})

        if not data:
            return {'message': 'No challenge was found ask for support'}

        return {'message': normalize(data)}

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            statement = {'title': title, 'content': content,
                         'duration': duration, 'modified': datetime.utcnow()}

            data = mongo.db.challenge.update_one(
                {'_id': ObjectId(args.id)}, {'$set': statement}, upsert=True)

            if data.modified_count > 0:
                return {'message': 'Challenge was successfully updated'}
            else:
                return {'message': 'Nothing to update already uptodate'}
        except Exception:
            return {'message': 'Something went wrong'}, 500


class ChallengeSubscribtion(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('challenge_id',
                                   type=str,
                                   required=False,
                                   help='No valid challenge id provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('user_id',
                                   type=str,
                                   required=False,
                                   help='No valid user id provided',
                                   location='json',
                                   nullable=False)

        super(ChallengeSubscribtion, self).__init__()

    @jwt_required
    @user_is('user')
    def get(self):
        results = []
        email = get_jwt_identity()

        user = mongo.db.users.find_one({'email': email})

        if not user:
            return {'message': 'User data was not found'}, 404

        # TODO: refoctor pythonic way with not
        if 'challenges' in user:
            results = mongo.db.challenge.find(
                {'_id': {'$in': [ObjectId(id) for id in user['challenges']]}})

        return {'message': normalize(results)}

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        challenge_id = args.challenge_id
        user_id = args.user_id

        query = {'_id': ObjectId(user_id), 'challenges': {
            '$in': [challenge_id]}}

        data = mongo.db.users.find_one(query)
        statement = {'challenges': challenge_id}

        if data:
            user = mongo.db.users.update_one(
                {'_id': ObjectId(user_id)}, {'$pull': statement}, upsert=True)

            if user.modified_count > 0:
                return {'message': 'User unsubscribed from challenge'}
            else:
                return {'message': 'Nothing to update already uptodate'}

        user = mongo.db.users.update_one(
            {'_id': ObjectId(user_id)}, {'$addToSet': statement}, upsert=True)

        if user.modified_count > 0:
            return {'message': 'User subscribed to challenge'}
        else:
            return {'message': 'Nothing to update already uptodate'}


class User(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('id',
                                   type=str,
                                   required=False,
                                   help='No valid user id provided',
                                   location='json',
                                   nullable=False)

        super(User, self).__init__()

    @jwt_required
    @user_is('admin')
    def get(self):
        users = mongo.db.users.find({}, {'password': 0})

        if not users:
            return {'message': 'No users were found ask for support'}, 404

        return {'message': normalize(users)}


class ChallengeTask(Resource):
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

        super(ChallengeTask, self).__init__()

    @jwt_required
    @user_is('user')
    def get(self):
        challenges = []

        for challenge in mongo.db.challenge.find():
            tasks = mongo.db.tasks.find({'cid': ObjectId(challenge['_id'])})

            if tasks:
                challenge['tasks'] = normalize(tasks)

            challenges.append(challenge)

        if not challenges:
            return {'message': 'No challenges were found create one'}, 404

        return {'message': normalize(challenges)}

    @jwt_required
    @user_is('admin')
    def post(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        challenge = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})

        if not challenge:
            return {'message': 'Challenge id was not found'}

        try:
            mongo.db.tasks.insert_one(
                {'cid': ObjectId(args.id), 'title': title, 'content': content,
                 'duration': duration, 'created': datetime.utcnow()})

            return {'message': 'Task was successfully added'}
        except Exception:
            return {'message': 'Something went wrong'}, 500


class ChallengeTaskDetail(Resource):
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

        super(ChallengeTaskDetail, self).__init__()

    @jwt_required
    @user_is('user')
    def post(self):
        args = self.reqparse.parse_args()

        data = mongo.db.tasks.find_one({'_id': ObjectId(args.id)})

        if not data:
            return {'message': 'No task was found ask for support'}

        return {'message': normalize(data)}

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        duration = args.duration

        try:
            statement = {'title': title, 'content': content,
                         'duration': duration, 'modified': datetime.utcnow()}

            data = mongo.db.tasks.update_one(
                {'_id': ObjectId(args.id)}, {'$set': statement}, upsert=True)

            if data.modified_count > 0:
                return {'message': 'Task was successfully updated'}
            else:
                return {'message': 'Nothing to update already uptodate'}
        except Exception:
            return {'message': 'Something went wrong'}, 500


class ChallengeTaskProgress(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('challenge_id',
                                   type=str,
                                   required=False,
                                   help='No valid challenge id provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('task_id',
                                   type=str,
                                   required=False,
                                   help='No valid task id provided',
                                   location='json',
                                   nullable=False)

        super(ChallengeTaskProgress, self).__init__()

    @jwt_required
    @user_is('user')
    def put(self):
        args = self.reqparse.parse_args()
        email = get_jwt_identity()

        challenge_id = args.challenge_id
        task_id = args.task_id

        query = {'email': email, 'progress': {
            '$in': [{'cid': challenge_id, 'tid': task_id}]}}

        data = mongo.db.users.find_one(query)
        statement = {'progress': {'cid': challenge_id, 'tid': task_id}}

        if data:
            user = mongo.db.users.update_one(
                {'email': email}, {'$pull': statement}, upsert=True)

            if user.modified_count > 0:
                return {'message': 'Changed task status to undone',
                        'progress': 'undone'}
            else:
                return {'message': 'Nothing to update already uptodate',
                        'progress': 'undone'}

        user = mongo.db.users.update_one(
            {'email': email}, {'$addToSet': statement}, upsert=True)

        if user.modified_count > 0:
            return {'message': 'Changed task status to done',
                    'progress': 'done'}
        else:
            return {'message': 'Nothing to update already uptodate',
                    'progress': 'done'}


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
                duration = int(Duration(r.get('{}tags?post={}'.format(
                    wpapi, str(post['id'])).json()[0]['name'])).to_seconds())
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

api.add_resource(User, '/user')

api.add_resource(Challenge, '/challenge')
api.add_resource(ChallengeDetail, '/challenge/detail')
api.add_resource(ChallengeSubscribtion, '/challenge/subscription')

api.add_resource(ChallengeTask, '/challenge/task')
api.add_resource(ChallengeTaskDetail, '/challenge/task/detail')
api.add_resource(ChallengeTaskProgress, '/challenge/task/progress')

api.add_resource(Fetch, '/fetch')


if __name__ == '__main__':
    app.run(debug=True)

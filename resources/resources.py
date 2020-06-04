#!/usr/bin/env python3

import re
import requests
import pytz

from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_refresh_token, jwt_required,
                                create_access_token, get_jwt_identity,
                                jwt_refresh_token_required)

from itsdangerous import (URLSafeTimedSerializer,
                          BadSignature, BadTimeSignature, SignatureExpired)

from datetime import datetime
from bson.objectid import ObjectId
from durations import Duration

# custom imports
from utils.mails import send_confirm_mail, send_reset_password_mail
from utils.decorators import user_is
from utils.utils import normalize
from app import app, bcrypt, mongo


# TODO: this value should be custommizable
wpapi = 'https://zackig.sbicego.ch/wp-json/wp/v2/'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
salt = app.config['SECRET_SALT']


def cleantext(text):
    return re.sub(r'<.*?>', '', text.replace('\n', '').replace('\r', ''))


class ConfirmToken(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('token',
                                   type=str,
                                   required=True,
                                   help='No valid token provided',
                                   location='json',
                                   nullable=False)

        super(ConfirmToken, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        try:
            email = serializer.loads(args.token, salt=salt, max_age=7200)
        except SignatureExpired:
            return {'message': 'Token expired ask for support'}, 401
        except BadTimeSignature:
            return {'message': 'Unknown error ask for support'}, 400
        except BadSignature:
            return {'message': 'Invalid token ask for support'}, 422

        user = mongo.db.users.find_one({'email': email})

        if not user:
            return {'message': 'User was not found on system'}, 404

        user = mongo.db.users.update_one(
            {'email': email}, {'$set': {'confirmed': datetime.utcnow()}})

        if user.matched_count > 0:
            return {'message': 'Successfully activated account'}
        else:
            return {'message': 'Unknown error ask for support'}, 400


class ResetPassword(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('email',
                                   type=str,
                                   required=True,
                                   help='No valid email provided',
                                   location='json',
                                   nullable=False)

        super(ResetPassword, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()

        try:
            user = mongo.db.users.find_one({'email': args.email})

            if not user:
                return {'message': 'Account was not found try again'}, 404

            if 'inactive' in user:
                return {'message': 'Account inactive ask for support'}, 400

            mail = send_reset_password_mail(user['name'], args.email)

            if not mail:
                return {'message': 'Error please try again'}, 400

            return {'message': 'Please check your inbox'}
        except Exception:
            return {'message': 'Something went wrong try again'}, 400


class UserSignup(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('name',
                                   type=str,
                                   required=True,
                                   help='No valid name provided',
                                   location='json',
                                   nullable=False)

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

        name = args.name
        email = args.email
        password = bcrypt.generate_password_hash(args.password)

        try:
            user = mongo.db.users.insert_one(
                {'name': name, 'email': email,
                 'password': password, 'roles': ['user']})

            if not user.inserted_id:
                return {'message': 'Something went wrong try again'}, 400

            mail = send_confirm_mail(name, email)

            if not mail:
                return {'message': 'Signup error please try again'}, 400

            return {'message': 'Please check your mail inbox'}
        except Exception:
            return {'message': 'Account already exists try to login'}, 409


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

        if not user:
            return {'message': 'Wrong password or email try again'}, 400

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

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
            return {'message': 'Wrong password or email try again'}, 400


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        email = get_jwt_identity()
        access_token = create_access_token(identity=email)

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

        self.reqparse.add_argument('from_date',
                                   type=str,
                                   required=False,
                                   help='No valid from date provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('to_date',
                                   type=str,
                                   required=False,
                                   help='No valid to date provided',
                                   location='json',
                                   nullable=False)

        super(Challenge, self).__init__()

    @jwt_required
    @user_is('user')
    def get(self):
        data = mongo.db.challenge.find()

        if not data:
            return {'message': 'No challenge was found ask for support'}

        return {'message': normalize(data)}

    @jwt_required
    @user_is('admin')
    def post(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content
        from_date = args.from_date
        to_date = args.to_date

        try:
            to_date = datetime.strptime(to_date, '%d-%m-%Y')
            from_date = datetime.strptime(from_date, '%d-%m-%Y')
            delta = to_date - from_date
        except Exception as e:
            print(e)
            return {'message': 'Invalid date string must be DD-MM-YYYY'}, 400

        try:
            mongo.db.challenge.insert_one(
                {'title': title, 'content': content, 'to': to_date,
                 'from': from_date, 'duration': delta.days,
                 'created': datetime.utcnow()})

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

        self.reqparse.add_argument('from_date',
                                   type=str,
                                   required=False,
                                   help='No valid from date provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('to_date',
                                   type=str,
                                   required=False,
                                   help='No valid to date provided',
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
        from_date = args.from_date
        to_date = args.to_date

        try:
            to_date = datetime.strptime(to_date, '%d-%m-%Y')
            from_date = datetime.strptime(from_date, '%d-%m-%Y')
            delta = to_date - from_date
        except Exception as e:
            print(e)
            return {'message': 'Invalid date string must be DD-MM-YYYY'}, 400

        try:
            statement = {'title': title, 'content': content, 'to': to_date,
                         'from': from_date, 'duration': delta.days,
                         'modified': datetime.utcnow()}

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
            return {'message': 'User was not found ask for support'}, 404

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

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

        self.reqparse.add_argument('name',
                                   type=str,
                                   required=False,
                                   help='No valid name provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('email',
                                   type=str,
                                   required=False,
                                   help='No valid email provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('roles',
                                   type=str,
                                   required=False,
                                   help='No valid roles provided',
                                   location='json',
                                   nullable=False)

        super(User, self).__init__()

    @jwt_required
    @user_is('user')
    def get(self):
        email = get_jwt_identity()

        user = mongo.db.users.find_one(
            {'email': email, 'inactive': {'$exists': False}}, {'password': 0})

        if not user:
            return {'message': 'User was not found ask for support'}, 404

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

        return {'message': normalize(user)}

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        name = args.name
        email = args.email
        roles = args.roles

        query = {'_id': ObjectId(args.id)}

        user = mongo.db.users.find_one(query)

        if not user:
            return {'message': 'User not found ask for support'}, 404

        try:
            if len(roles.split(',')) > 0:
                roles = [r.strip() for r in roles.split(',')]

            statement = {'name': name, 'email': email,
                         'modified': datetime.utcnow(), 'roles': roles}

            mongo.db.users.update_one(query, {'$set': statement})

            return {'message': 'User was successfully updated'}
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong'}, 500

    @jwt_required
    @user_is('admin')
    def delete(self, id):
        email = get_jwt_identity()

        user = mongo.db.users.find_one({'_id': ObjectId(id)})

        if user['email'] == email:
            return {'message': 'Can not change status on own account'}, 403

        user = mongo.db.users.update_one(
            {'_id': ObjectId(id)}, {'$set': {'inactive': True}})

        if user.matched_count > 0:
            return {'message': 'User status was set to inactive'}

        return {'message': 'User not found ask for support'}, 404


class UserList(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('id',
                                   type=str,
                                   required=False,
                                   help='No valid user id provided',
                                   location='json',
                                   nullable=False)

        super(UserList, self).__init__()

    @jwt_required
    @user_is('admin')
    def get(self):
        users = mongo.db.users.find(
            {'inactive': {'$exists': False}}, {'password': 0})

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

        self.reqparse.add_argument('from_date',
                                   type=str,
                                   required=False,
                                   help='No valid from date provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('to_date',
                                   type=str,
                                   required=False,
                                   help='No valid to date provided',
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
        from_date = args.from_date
        to_date = args.to_date

        challenge = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})

        if not challenge:
            return {'message': 'Challenge id was not found'}

        try:
            to_date = datetime.strptime(to_date, '%d-%m-%Y')
            from_date = datetime.strptime(from_date, '%d-%m-%Y')
            delta = to_date - from_date
        except Exception as e:
            print(e)
            return {'message': 'Invalid date string must be DD-MM-YYYY'}, 400

        try:
            mongo.db.tasks.insert_one(
                {'cid': ObjectId(args.id), 'title': title,
                 'content': content, 'from': from_date, 'to': to_date,
                 'duration': delta.days, 'created': datetime.utcnow()})

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

        self.reqparse.add_argument('from_date',
                                   type=str,
                                   required=False,
                                   help='No valid from date provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('to_date',
                                   type=str,
                                   required=False,
                                   help='No valid to date provided',
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
        from_date = args.from_date
        to_date = args.to_date

        try:
            to_date = datetime.strptime(to_date, '%d-%m-%Y')
            from_date = datetime.strptime(from_date, '%d-%m-%Y')
            delta = to_date - from_date
        except Exception as e:
            print(e)
            return {'message': 'Invalid date string must be DD-MM-YYYY'}, 400

        try:
            statement = {'title': title, 'content': content, 'to': to_date,
                         'from': from_date, 'duration': delta.days,
                         'modified': datetime.utcnow()}

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


class LandingPage(Resource):
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

        super(LandingPage, self).__init__()

    @jwt_required
    @user_is('user')
    def get(self):
        landing = mongo.db.pages.find_one({'type': 'landing'})

        if not landing:
            return {'message': 'No content was found ask for support'}

        return {'message': normalize(landing)}

    @jwt_required
    @user_is('admin')
    def post(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content

        try:
            mongo.db.pages.insert_one(
                {'title': title, 'content': content,
                 'type': 'landing', 'created': datetime.utcnow()})

            return {'message': 'Page was successfully created'}
        except Exception:
            return {'message': 'Something went wrong try again'}, 500

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        title = args.title
        content = args.content

        try:
            statement = {'title': title, 'content': content,
                         'modified': datetime.utcnow()}

            data = mongo.db.pages.update_one(
                {'_id': ObjectId(args.id)}, {'$set': statement}, upsert=True)

            if data.modified_count > 0:
                return {'message': 'Page was successfully updated'}
            else:
                return {'message': 'Nothing to update already uptodate'}
        except Exception:
            return {'message': 'Something went wrong ask for supoort'}, 500


class Fetch(Resource):
    @jwt_required
    @user_is('admin')
    def get(self):
        i = 0
        j = 0

        posts = requests.get(wpapi + 'posts').json()
        timezone = pytz.timezone('Europe/Zurich')

        for post in posts:
            challenge = mongo.db.challenge.find_one({'wpid': post['id']})

            created = timezone.localize(datetime.strptime(
                post['date'], '%Y-%m-%dT%H:%M:%S'))
            modified = timezone.localize(datetime.strptime(
                post['modified'], '%Y-%m-%dT%H:%M:%S'))

            try:
                duration = int(Duration(requests.get('{}tags?post={}'.format(
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

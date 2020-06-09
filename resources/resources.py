#!/usr/bin/env python3

import os
import re
import requests
import pytz
import csv
import io

from flask import Response, request
from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_refresh_token, jwt_required,
                                create_access_token, get_jwt_identity,
                                jwt_refresh_token_required)

from itsdangerous import (URLSafeTimedSerializer,
                          BadSignature, BadTimeSignature, SignatureExpired)

from datetime import datetime
from bson.objectid import ObjectId
from durations import Duration
from pathlib import Path
from uuid import uuid4

# custom imports
from utils.mails import send_confirm_mail, send_reset_password_mail
from utils.utils import normalize, logging, browser, non_empty_string
from utils.decorators import user_is
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


class ChangePassword(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('token',
                                   type=str,
                                   required=True,
                                   help='No valid token provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('password',
                                   type=str,
                                   required=True,
                                   help='No valid password provided',
                                   location='json',
                                   nullable=False)

        super(ChangePassword, self).__init__()

    def put(self):
        args = self.reqparse.parse_args()

        password = bcrypt.generate_password_hash(args.password)

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
            return {'message': 'Account was not found try again'}, 404

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

        user = mongo.db.users.update_one(
            {'email': email}, {'$set': {'password': password}})

        if user.matched_count > 0:
            return {'message': 'Successfully updated password'}
        else:
            return {'message': 'Something went wrong try again'}, 400


class UserChangePassword(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('confirm',
                                   type=str,
                                   required=True,
                                   help='No valid confirm provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('password',
                                   type=str,
                                   required=True,
                                   help='No valid password provided',
                                   location='json',
                                   nullable=False)

        super(UserChangePassword, self).__init__()

    @jwt_required
    @user_is('user')
    def put(self, id):
        email = get_jwt_identity()
        args = self.reqparse.parse_args()

        confirm = args.confirm
        password = args.password

        if confirm != password:
            return {'message': 'Passwords does not match try again'}, 401

        password = bcrypt.generate_password_hash(args.password)

        user = mongo.db.users.find_one({'_id': ObjectId(id)})

        if user['email'] != email:
            return {'message': 'Not authorized request reported'}, 403

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

        user = mongo.db.users.update_one(
            {'_id': ObjectId(id)}, {'$set': {'password': password}})

        if user.matched_count > 0:
            return {'message': 'Successfully updated password'}
        else:
            return {'message': 'Something went wrong try again'}, 400


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
        except Exception as e:
            print(e)
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

            mongo.db.logs.insert_one(logging(user['_id'], request, 'signin'))

            try:
                avatar = user['avatar']
            except Exception:
                avatar = None

            return {
                'message': 'Logged in as {}'.format(email),
                'refresh_token': refresh_token,
                'access_token': access_token,
                'roles': user['roles'],
                'id': str(user['_id']),
                'name': user['name'],
                'avatar': avatar
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
        challenge = mongo.db.challenge.find({'archived': {'$exists': False}})

        if not challenge:
            return {'message': 'No challenge was found ask for support'}

        return {'message': normalize(challenge)}

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

    @jwt_required
    @user_is('admin')
    def delete(self, id):
        challenge = mongo.db.challenge.update_one(
            {'_id': ObjectId(id)}, {'$set': {'archived': True}})

        if challenge.matched_count > 0:
            return {'message': 'Challenge status was set to archived'}

        return {'message': 'Challenge not found ask for support'}, 404


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

        challenge = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})

        if not challenge:
            return {'message': 'No challenge was found ask for support'}

        if 'archived' in challenge:
            return {'message': 'Challenge is archived ask for support'}, 400

        return {'message': normalize(challenge)}

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

        challenges = [ObjectId(id) for id in user['challenges']]

        # TODO: refoctor pythonic way with not
        if 'challenges' in user:
            results = mongo.db.challenge.find(
                {'_id': {'$in': challenges}, 'archived': {'$exists': False}})

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


class UserChallenge(Resource):
    @jwt_required
    @user_is('user')
    def get(self):
        email = get_jwt_identity()

        user = mongo.db.users.find_one({'email': email})

        if not user:
            return {'message': 'Account not found ask for support'}, 404

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

        if 'challenges' not in user:
            return {'message': 'Account not subscribed to any challenge'}, 404

        for cid in user['challenges']:
            challenges = mongo.db.challenge.find(
                {'_id': ObjectId(cid), 'archived': {'$exists': False}})

        array = []

        for challenge in challenges:
            query = {'cid': ObjectId(challenge['_id']),
                     'archived': {'$exists': False}}
            tasks = mongo.db.tasks.find(query)

            if tasks:
                challenge['tasks'] = []

                for task in normalize(tasks):
                    if 'progress' in user:
                        for progress in user['progress']:
                            if task['_id'] == progress['tid']:
                                task['progress'] = 'done'

                    challenge['tasks'].append(task)

            array.append(challenge)

        return {'message': normalize(array)}


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


class UserProfile(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('name',
                                   type=non_empty_string,
                                   help='No valid name provided',
                                   location='json',
                                   required=True,
                                   nullable=False)

        self.reqparse.add_argument('username',
                                   type=str,
                                   help='No valid username provided',
                                   location='json',
                                   required=False,
                                   nullable=False)

        self.reqparse.add_argument('email',
                                   type=non_empty_string,
                                   help='No valid email provided',
                                   location='json',
                                   required=True,
                                   nullable=False)

        self.reqparse.add_argument('location',
                                   type=str,
                                   help='No valid location provided',
                                   location='json',
                                   required=False,
                                   nullable=False)

        self.reqparse.add_argument('website',
                                   type=str,
                                   help='No valid website provided',
                                   location='json',
                                   required=False,
                                   nullable=False)

        self.reqparse.add_argument('phone',
                                   type=str,
                                   help='No valid phone provided',
                                   location='json',
                                   required=False,
                                   nullable=False)

        self.reqparse.add_argument('bio',
                                   type=str,
                                   help='No valid bio provided',
                                   location='json',
                                   required=False,
                                   nullable=False)

        super(UserProfile, self).__init__()

    @jwt_required
    @user_is('user')
    def put(self, id):
        args = self.reqparse.parse_args()

        name = args.name
        email = args.email
        username = args.username
        location = args.location
        website = args.website
        phone = args.phone
        bio = args.bio

        query = {'_id': ObjectId(id)}

        user = mongo.db.users.find_one(query)

        if not user:
            return {'message': 'User not found ask for support'}, 404

        statement = {'name': name, 'email': email, 'username': username,
                     'website': website, 'location': location, 'bio': bio,
                     'phone': phone, 'modified': datetime.utcnow()}

        user = mongo.db.users.update_one(query, {'$set': statement})

        if user.matched_count > 0:
            return {'message': 'User was successfully updated'}
        else:
            return {'message': 'Nothing to update already uptodate'}


class UserAvatar(Resource):
    @jwt_required
    @user_is('user')
    def post(self, id):
        avatar = '{}.png'.format(str(uuid4()))

        try:
            request.files['file'].save(os.path.join(
                app.root_path, 'static', avatar))
        except Exception as e:
            print(e)
            return {'message': 'Error uploading avatar try again'}, 400

        file = Path(os.path.join(app.root_path, 'static', avatar))

        if not file.exists():
            return {'message': 'Error uploading avatar try again'}, 400

        query = {'_id': ObjectId(id)}
        user = mongo.db.users.find_one(query)

        if not user:
            return {'message': 'User not found ask for support'}, 404

        statement = {'avatar': avatar, 'modified': datetime.utcnow()}

        user = mongo.db.users.update_one(query, {'$set': statement})

        if user.modified_count > 0:
            return {
                'message': 'Avatar was successfully uploaded',
                'avatar': avatar
            }
        else:
            return {'message': 'Oooops something went wrong'}, 400

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
        challenges = mongo.db.challenge.find({'archived': {'$exists': False}})
        array = []

        for challenge in challenges:
            tasks = mongo.db.tasks.find({'cid': ObjectId(challenge['_id'])})

            if tasks:
                challenge['tasks'] = []

                for task in normalize(tasks):
                    if 'archived' not in task:
                        challenge['tasks'].append(task)

            array.append(challenge)

        if not array:
            return {'message': 'No challenges were found create one'}, 404

        return {'message': normalize(array)}

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

        if 'archived' in challenge:
            return {'message': 'Challenge is archived ask for support'}, 400

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

    @jwt_required
    @user_is('admin')
    def delete(self, id):
        challenge = mongo.db.tasks.update_one(
            {'_id': ObjectId(id)}, {'$set': {'archived': True}})

        if challenge.matched_count > 0:
            return {'message': 'Task status was set to archived'}

        return {'message': 'Task not found ask for support'}, 404


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

        task = mongo.db.tasks.find_one({'_id': ObjectId(args.id)})

        if not task:
            return {'message': 'No task was found ask for support'}

        if 'archived' in task:
            return {'message': 'Task is archived ask for support'}, 400

        return {'message': normalize(task)}

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
            return {'message': 'Content was not found ask for support'}, 400

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


class MailTemplate(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('id',
                                   type=str,
                                   required=False,
                                   help='No valid id provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('type',
                                   type=str,
                                   required=False,
                                   help='No valid type provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('subject',
                                   type=str,
                                   required=False,
                                   help='No valid subject provided',
                                   location='json',
                                   nullable=False)

        self.reqparse.add_argument('message',
                                   type=str,
                                   required=False,
                                   help='No valid message provided',
                                   location='json',
                                   nullable=False)

        super(MailTemplate, self).__init__()

    @jwt_required
    @user_is('admin')
    def get(self, id):
        template = mongo.db.templates.find_one({'_id': id})

        if not template:
            return {'message': 'Template not found ask for support'}, 404

        return {'message': normalize(template)}

    @jwt_required
    @user_is('admin')
    def post(self):
        args = self.reqparse.parse_args()

        type = args.type
        subject = args.subject
        message = args.message

        try:
            template = mongo.db.templates.insert_one(
                {'subject': subject, 'message': message,
                 'type': type, 'created': datetime.utcnow()})

            return {'message': 'Template was successfully created',
                    '_id': str(template.inserted_id)}
        except Exception:
            return {'message': 'Something went wrong try again'}, 500

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()

        subject = args.subject
        message = args.message

        try:
            statement = {'subject': subject, 'message': message,
                         'modified': datetime.utcnow()}

            template = mongo.db.templates.update_one(
                {'_id': ObjectId(args.id)}, {'$set': statement}, upsert=True)

            if template.modified_count > 0:
                return {'message': 'Template was successfully updated'}
            else:
                return {'message': 'Nothing to update already uptodate'}
        except Exception:
            return {'message': 'Something went wrong ask for supoort'}, 500


class MailTemplateList(Resource):
    @jwt_required
    @user_is('admin')
    def get(self):
        templates = mongo.db.templates.find()

        if not templates:
            return {'message': 'No template was found create one'}, 404

        return {'message': normalize(templates)}


class UserLastseen(Resource):
    @jwt_required
    @user_is('user')
    def get(self, id):
        email = get_jwt_identity()

        user = mongo.db.users.find_one({'_id': ObjectId(id)})

        if not user:
            return {'message': 'Not authorized request reported'}, 403

        if user['email'] != email:
            return {'message': 'Not authorized request reported'}, 403

        logs = mongo.db.logs.find(
            {'uid': ObjectId(id), 'action': 'signin'}).sort([('created', -1)])

        if not logs:
            return {'message': 'No logs were found fresh page'}, 404

        array = []

        for log in normalize(logs, 'datetime'):
            array.append({
                'browser': browser(log['useragent']),
                'datetime': log['created'],
                'address': log['address']
            })

        return {'message': array}


class UserExport(Resource):
    @jwt_required
    @user_is('user')
    def get(self):
        users = mongo.db.users.find(
            {}, {'_id': 0, 'name': 1, 'inactive': 1, 'email': 1,
                 'challenges': 1, 'progress': 1})

        if not users:
            return {'message': 'No users were found ask for support'}, 400

        dest = io.StringIO()
        writer = csv.writer(dest, quoting=csv.QUOTE_ALL)
        writer.writerow(['email', 'full name', 'user status',
                         'subscribtion', 'tasks done'])

        for user in normalize(users):
            items = ['', '', '', '', '']

            for key, value in user.items():
                if key == 'name':
                    items[1] = value
                if key == 'email':
                    items[0] = value
                if key == 'inactive':
                    items[2] = 'inactive'
                if key == 'progress':
                    items[4] = ','.join([c['tid'] for c in value])
                if key == 'challenges':
                    items[3] = ','.join([c for c in value])

            if items[2] == '':
                items[2] = 'active'

            writer.writerow(items)

        content = {
            'Content-Disposition': 'attachment; filename=export.csv'}

        return Response(dest.getvalue(), mimetype='text/csv', headers=content)


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


class RequestChallenge(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)

        self.reqparse.add_argument('id',
                                   type=str,
                                   required=True,
                                   help='No valid id provided',
                                   location='json',
                                   nullable=False)

        super(RequestChallenge, self).__init__()

    @jwt_required
    @user_is('admin')
    def get(self):
        # TODO: add a new endpoint RequestChallengeList dont use request args
        args = request.args

        if 'showall' in args:
            if args['showall'] == 'true':
                requests = mongo.db.challengerequests.find()
                return {'message': normalize(requests)}

        requests = mongo.db.challengerequests.find_one(
            {'accepted': {'$eq': False}})

        return {'message': normalize(requests)}

    @jwt_required
    @user_is('user')
    def post(self):
        args = self.reqparse.parse_args()
        email = get_jwt_identity()

        user = mongo.db.users.find_one({'email': email})

        try:
            ObjectId(args.id)
        except Exception:
            return {'message': 'The provided id is not valid'}, 400

        if not user:
            return {'message': 'Account not found ask for support'}, 404

        if 'inactive' in user:
            return {'message': 'Account inactive ask for support'}, 400

        challenge = mongo.db.challenge.find_one({'_id': ObjectId(args.id)})

        if not challenge:
            return {'message': 'This challenge doesn\'t exist'}, 404

        if str(args.id) in user['challenges']:
            return {
                'message': 'You are already subscribed to this challenge'
            }, 400

        challengerequest = mongo.db.challengerequests.find_one(
            {'uid': ObjectId(user['_id']), 'cid': ObjectId(args.id)})

        if challengerequest:
            return {
                'message': 'You already requested access to this challenge'
            }, 400

        statement = {'uid': ObjectId(user['_id']), 'cid': ObjectId(
            args.id), 'created': datetime.utcnow(), 'accepted': False}

        mongo.db.challengerequests.insert_one(statement)

        return {'message': normalize({})}

    @jwt_required
    @user_is('admin')
    def put(self):
        args = self.reqparse.parse_args()
        email = get_jwt_identity()

        args = request.args

        user = mongo.db.users.find_one({'email': email})

        try:
            ObjectId(args.id)
        except Exception:
            return {'message': 'The provided id is not valid'}, 400

        challengerequest = mongo.db.challengerequests.find_one(
            {'_id': ObjectId(args.id)})

        if not challengerequest:
            return {'message': 'Request doesn\'t exist ask for support'}, 404

        statement = {'accepted': True, 'acceptedby': user['_id'],
                     'modified': datetime.utcnow()}

        mongo.db.challengerequests.update_one(
            {'_id': args.id}, {'$set': statement})

        statement = {'$addToSet': {
            'challenges': ObjectId(challengerequest['cid'])}}

        user = mongo.db.users.update_one(
            {'_id': ObjectId(challengerequest['uid'])}, statement, upsert=True)

        if user.modified_count > 0:
            return {'message': 'User subscribed to requested challenge'}
        else:
            return {'message': 'Nothing to update already uptodate'}, 400

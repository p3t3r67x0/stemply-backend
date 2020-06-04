#!/usr/bin/env python3

# custom imports
from app import app, api, mongo
from resources import resources as res


api.add_resource(res.UserSignup, '/signup')
api.add_resource(res.UserSignin, '/signin')
api.add_resource(res.TokenRefresh, '/token/refresh')

api.add_resource(res.ConfirmToken, '/confirm')

api.add_resource(res.User, '/user', '/user/<string:id>')
api.add_resource(res.UserList, '/user/list')

api.add_resource(res.Challenge, '/challenge')
api.add_resource(res.ChallengeDetail, '/challenge/detail')
api.add_resource(res.ChallengeSubscribtion, '/challenge/subscription')

api.add_resource(res.ChallengeTask, '/challenge/task')
api.add_resource(res.ChallengeTaskDetail, '/challenge/task/detail')
api.add_resource(res.ChallengeTaskProgress, '/challenge/task/progress')

api.add_resource(res.LandingPage, '/landing')
api.add_resource(res.Fetch, '/fetch')

# create index on collections
mongo.db.users.create_index([('email', 1)], unique=True)


if __name__ == '__main__':
    app.run(debug=True)

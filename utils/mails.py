#!/usr/bin/env python3

from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer

# custom imports
from app import mongo, mail, app


app_url = app.config['APP_URL']
sender = app.config['MAIL_USERNAME']
secret_salt = app.config['SECRET_SALT']
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def send_reset_password_mail(name, email):
    confirm_token = serializer.dumps(email, salt=secret_salt)

    template = mongo.db.templates.find_one({'type': 'reset'})

    if not template:
        subject_content = '%NAME% reset your password'
        message_content = app.config['RESET_PASSWORD_BODY']
    else:
        subject_content = template['subject']
        message_content = template['message']

    subject = subject_content.replace('%NAME%', name)
    message = message_content.replace('%NAME%', name).replace(
        '%LINK%', '{}/change/{}'.format(app_url, confirm_token))

    msg = Message(subject=subject, sender=sender, recipients=[email])
    msg.body = message

    mail.send(msg)

    return True


def send_confirm_mail(name, email):
    confirm_token = serializer.dumps(email, salt=secret_salt)

    template = mongo.db.templates.find_one({'type': 'confirm'})

    if not template:
        subject_content = '%NAME% confirm your account'
        message_content = app.config['CONFIRM_MAIL_BODY']
    else:
        subject_content = template['subject']
        message_content = template['message']

    subject = subject_content.replace('%NAME%', name)
    message = message_content.replace('%NAME%', name).replace(
        '%LINK%', '{}/confirm/{}'.format(app_url, confirm_token))

    msg = Message(subject=subject, sender=sender, recipients=[email])
    msg.body = message

    mail.send(msg)

    return True

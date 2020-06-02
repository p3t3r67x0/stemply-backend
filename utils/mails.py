#!/usr/bin/env python3

from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer

# custom imports
from app import mail, app


app_url = app.config['APP_URL']
sender = app.config['MAIL_USERNAME']
secret_salt = app.config['SECRET_SALT']
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def send_reset_password_mail(name, email):
    confirm_token = serializer.dumps(email, salt=secret_salt)
    subject = '{} reset your password'.format(name)
    msg = Message(subject=subject, sender=sender, recipients=[email])

    msg.body = 'Hello {},\n\nwith this mail we send you the link to reset \
    your password for your Education account.\n\n{}/change/{}\n\nBest \
    regards\nEducation Team'.format(name, app_url, confirm_token)

    mail.send(msg)

    return True


def send_confirm_mail(name, email):
    confirm_token = serializer.dumps(email, salt=secret_salt)
    subject = '{} confirm your account'.format(name)
    msg = Message(subject=subject, sender=sender, recipients=[email])

    msg.body = 'Hello {},\n\nwith this mail we send you the confirmation \
    link for your Education account.\n\n{}/confirm/{}\n\nBest regards\n \
    Education Team'.format(name, app_url, confirm_token)

    mail.send(msg)

    return True

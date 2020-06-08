#!/usr/bin/env python3

from datetime import datetime
from ua_parser.user_agent_parser import ParseUserAgent
from bson.objectid import ObjectId
from pymongo.cursor import Cursor


def analyze(o, f):
    d = {}

    for k, v in o.items():
        if isinstance(v, ObjectId):
            d[k] = str(v)
        elif isinstance(v, datetime):
            if f == 'date':
                d[k] = v.strftime('%d-%m-%Y')
            elif f == 'datetime':
                d[k] = v.strftime('%d.%m.%Y %H:%M')
        elif isinstance(v, bytes):
            d[k] = str(v)
        elif isinstance(v, bool):
            d[k] = str(v)
        else:
            d[k] = v

    return d


def normalize(objects, format='date'):
    if isinstance(objects, list) or isinstance(objects, Cursor):
        array = []

        for object in objects:
            array.append(analyze(object, format))

        return array
    elif isinstance(objects, dict):
        return analyze(objects, format)


def logging(id, req, action):
    address = req.remote_addr
    useragent = str(req.user_agent)
    date = datetime.utcnow()

    statement = {'uid': id, 'useragent': useragent,
                 'created': date, 'address': address, 'action': action}

    return statement


def browser(ua_string):
    parsed_string = ParseUserAgent(ua_string)
    browser = '{} {}'.format(parsed_string['family'], parsed_string['major'])

    return browser


def non_empty_string(s):
    if not s:
        raise ValueError('Must not be empty string')

    return s

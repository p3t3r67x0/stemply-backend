#!/usr/bin/env python3

from datetime import datetime
from bson.objectid import ObjectId
from pymongo.cursor import Cursor


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

#!/usr/bin/env python3

from flask import Flask, jsonify

app = Flask(__name__)
app.config.from_json('config.json')


@app.route('/')
def index():
    return jsonify({'message': 'Thanks for visiting api.stemply.me'}), 404


if __name__ == '__main__':
    app.run(debug=True)

# zackig-backend


## Usage

```bash
curl http://127.0.0.1:5000/api/v1/signin
```

A possible response could look like this

```json
{
  "message": {
    "username": "No valid username provided",
    "password": "No valid password provided"
  }
}
```

Signin or signup by default routes `\signin` or `\signup`

```bash
curl -X POST http://127.0.0.1:5000/api/v1/signin \
-d '{"username":"YOUR_USERNAME_HERE", "password":"YOUR_PASSWORD_HERE"}' \
-H "Content-Type: application/json"
```

```bash
curl -X POST http://127.0.0.1:5000/api/v1/signup \
-d '{"username":"YOUR_USERNAME_HERE", "password":"YOUR_PASSWORD_HERE"}' \
-H "Content-Type: application/json"
```

Call a protected resource for example the route `\challenges`

```bash
curl -X GET http://127.0.0.1:5000/api/v1/challenges \
-H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```


## Prerequisites

Create a `config.json` file in the `/` folder

```json
{
  "SECRET_KEY": "YOUR_SECRET_KEY_HERE",
  "MONGO_URI": "mongodb://127.0.0.1:27017/zackig",
  "JWT_SECRET_KEY": "YOUR_JWT_SECRET_KEY_HERE"
}
```

## Build Setup

```bash
# install build dependencies
sudo apt install virtualenv python3.8 python3.8-dev

# create a virtualenv
virtualenv -p /usr/bin/python3.8 venv

# activate virtualenv
. venv/bin/activate

# install dependencies
pip3 install -r requirements.txt

# serve at 127.0.0.1:5000
gunicorn --bind 127.0.0.1:5000 wsgi:app --access-logfile - --error-logfile - --log-level debug
```

## Systemd Setup

Create a file `/etc/systemd/system/stemply.service` with following content

```bash
[Unit]
Description=Gunicorn instance to serve stemply
After=network.target

[Service]
User=<USER>
Group=www-data
WorkingDirectory=/home/<USER>/git/stemply-webapp/api
Environment="PATH=/home/<USER>/git/stemply-webapp/api/venv/bin"
ExecStart=/home/<USER>/git/stemply-webapp/api/venv/bin/gunicorn --bind 127.0.0.1:5000 wsgi:app --workers 4 --threads 2 --access-logfile /var/log/stemply/access.log --error-logfile /var/log/stemply/error.log --log-level INFO
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Start the service and enable the service

```bash
sudo systemctl start stemply
sudo systemctl enable stemply
```

## Setup Nginx with SSL

Install dependencies from Ubuntu repository

```bash
sudo apt install nginx-full certbot python-certbot-nginx
```

Setup nginx config file in `/etc/nginx/sites-enabled/api_example_com`

```cfg
server {
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Port $server_port;
    }
}
```

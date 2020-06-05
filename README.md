# zackig-backend


## Usage

```bash
curl http://127.0.0.1:5000/api/v1/signin
```

A possible response could look like this

```json
{
  "message": {
    "email": "No valid email provided",
    "password": "No valid password provided"
  }
}
```

Signin or signup by default routes `/signin` or `/signup`

```bash
curl -X POST http://127.0.0.1:5000/api/v1/signin \
-d '{"email":"YOUR_USERNAME_HERE", "password":"YOUR_PASSWORD_HERE"}' \
-H "Content-Type: application/json"
```

```bash
curl -X POST http://127.0.0.1:5000/api/v1/signup \
-d '{"email":"YOUR_USERNAME_HERE", "password":"YOUR_PASSWORD_HERE"}' \
-H "Content-Type: application/json"
```

Call a protected resource for example the route `/challenges`

```bash
curl -X GET http://127.0.0.1:5000/api/v1/challenges \
-H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

Fetch latest entries from wordpress json api with `/fetch`

```bash
curl -X GET http://127.0.0.1:5000/api/v1/fetch \
-H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

## Prerequisites

Create a `config.json` file in the `/` folder

```json
{
  "SECRET_KEY": "YOUR_SECRET_KEY_HERE",
  "SECRET_SALT": "YOUR_SECRET_SALT_HERE",
  "JWT_SECRET_KEY": "YOUR_JWT_SECRET_KEY_HERE",
  "MONGO_URI": "mongodb://127.0.0.1:27017/zackig",
  "MAIL_RECIPIENT": "MAIL_RECIPIENT_HERE",
  "MAIL_SERVER": "smtp.gmail.com",
  "MAIL_PORT": "465",
  "MAIL_USERNAME": "YOUR_MAIL_USERNAME_HERE",
  "MAIL_PASSWORD": "YOUR_SECURE_PASSWORD_HERE",
  "MAIL_USE_TLS": false,
  "MAIL_USE_SSL": true,
  "PROPAGATE_EXCEPTIONS": true,
  "APP_URL": "YOUR_APP_URL_HERE",
  "RESET_PASSWORD_BODY": "Hello %NAME%,\n\nwith this mail we send you the link to reset your password for your Education account.\n\n%LINK%\n\nBest regards\nEducation Team",
  "CONFIRM_MAIL_BODY": "Hello %NAME%,\n\nwith this mail we send you the confirmation link for your Education account.\n\n%LINK%\n\nBest regards\nEducation Team"
}
```


## Setup MongoDB

```bash
docker pull mongo
```

Run mongodb with docker and some parameters below

```bash
docker run --name mongodb --restart always -d \
-p 127.0.0.1:27017:27017 -v ~/data:/data/db mongo:latest
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

Create a file `/etc/systemd/system/zackig-api.service` with following content

```bash
[Unit]
Description=Gunicorn instance to serve zackig-api
After=network.target

[Service]
User=<USER>
Group=www-data
WorkingDirectory=/home/<USER>/git/zackig-api-backend
Environment="PATH=/home/<USER>/git/zackig-api-backend/venv/bin"
ExecStart=/home/<USER>/git/zackig-api-backend/venv/bin/gunicorn --bind 127.0.0.1:5000 wsgi:app --workers 4 --threads 2 --access-logfile /var/log/zackig-api/access.log --error-logfile /var/log/zackig-api/error.log --log-level INFO
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Start the service and enable the service

```bash
sudo systemctl start zackig-api
sudo systemctl enable zackig-api
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

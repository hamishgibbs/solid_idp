import requests as r

# Login workflow to recieve a JWT
creds = {"username": "test", "password": "secret"}

login_res = r.post('http://127.0.0.1:8000/token', data = creds)

login_res.status_code
login_res.json()

# Account regsitration workflow
creds = {"username": "test",
         "password": "secret",
         "email": "test@test.com",
         "full_name": "testy test",
         "disabled": "False"}

login_res = r.post('http://127.0.0.1:8000/register', data = creds)

login_res.status_code
login_res.text

# OIDC registration document workflow
login_res = r.get('http://127.0.0.1:8000/test/card')

login_res.status_code
login_res.text

# Django JWT Login sample with Django REST Framework

Just for personal PoC.

## Setup

```
# generate key-pair
ssh-keygen -t rsa -b 4096 -f jwtRS256.key -q -N ""

# convert .pub to PEM format
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub

# prepare for venv
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```
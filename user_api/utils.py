import base64

from django.conf import settings
from datetime import datetime, timedelta
import jwt
import random


def generate_access_token(user):
    payload = {
        'user_id': user.user_id,
        'exp': datetime.utcnow() + timedelta(days=1, minutes=0),
        'iat': datetime.utcnow(),
    }

    access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return access_token


def generate_random_image_name(userid, name):
    split = name.split(".")
    payload = f"{userid}"
    chars = ["AaBbCcDdEeFfGgHhXxZz123456789"]
    payload.join(random.choices(chars, k=20))
    payload + "_" + datetime.now().strftime("%m/%d/%Y")
    payload_bytes = payload.encode("ascii")
    payload_base64 = base64.b64encode(payload_bytes)
    return payload_base64.decode("utf-8") + "." + split[1]

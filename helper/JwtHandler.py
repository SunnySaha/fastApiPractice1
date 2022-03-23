import time
from jose import JWTError, jwt
from decouple import config
from datetime import datetime, timedelta
from typing import Dict

JWT_SECRET = config('SECRET')
JWT_ALGORITHM = config('ALGORITHM')
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = config('ACCESS_TOKEN_EXPIRE_MINUTES')


def generated_token(token: str):
    return {
        'access_token': token
    }


def sign_jwt(user_id: str):
    payload = {
        "user_id": user_id,
        "expires": time.time() + 36000
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return generated_token(token)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


# async def decode_token(token: str):
#     decoded_token = await jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHM)
#     return decoded_token if decoded_token['expire'] >= time.time() else None


def decode_token(token: str):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {'ss': 'something wrong'}

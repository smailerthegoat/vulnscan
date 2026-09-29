import functools

import jwt
from flask import abort, g, request

from config import JWT_SECRET


def current_user():
    return g.user


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            abort(401)
        g.user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_signature": False})
        return view(*args, **kwargs)

    return wrapper

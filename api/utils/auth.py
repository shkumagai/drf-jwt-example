import jwt

from datetime import datetime, timedelta, timezone
from pathlib import Path

from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions

from api.models import UserInfo


class NormalAuthentication(BaseAuthentication):
    def authenticate(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")
        user_obj = UserInfo.objects.filter(username=username).first()
        if not user_obj:
            raise exceptions.AuthenticationFailed("Authentication failed")
        elif user_obj.password != password:
            raise exceptions.AuthenticationFailed("Authnetication failed")
        token = generate_jwt(user_obj)
        return (token, None)

    def authenticate_header(self, request):
        pass


def generate_jwt(user):
    payload = {
        "iss": "",
        "sub": "",
        "uid": user.id,
        "username": user.username,
        "info": user.info,
    }
    return jwt.encode(payload, settings.SHARED_SECRET, algorithm=settings.SIGNING_ALGORITHM)


class JWTAuthentication(BaseAuthentication):
    keyword = "JWT"

    def authenticate(self, request):
        try:
            auth_type, token = get_authorization_header(request).split()

            if auth_type.lower() != self.keyword.lower().encode():
                return None
        except Exception as why:
            raise exceptions.AuthenticationFailed("Invalid authorization header format") from why

        try:
            jwt_info = jwt.decode(token, settings.SHARED_SECRET, algorithms=[settings.SIGNING_ALGORITHM])
            user = UserInfo.objects.get(pk=jwt_info.get("uid"))
            user.is_authenticated = True
            return (user, token)
        except Exception as why:
            raise exceptions.AuthenticationFailed("Authorization failed") from why

    def authenticate_header(self, request):
        pass

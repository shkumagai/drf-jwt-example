from datetime import datetime, timedelta, timezone
from pathlib import Path

from jwt import JWT, jwk_from_pem
from jwt.exceptions import JWTDecodeError
from jwt.utils import get_int_from_datetime

from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions

from api.models import UserInfo


instance = JWT()
signing_key_path = Path(settings.BASE_DIR) / settings.SIGNING_KEY_NAME
verifying_key_path = Path(settings.BASE_DIR) / settings.VERIFYING_KEY_NAME


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
        "iss": "https://vq.visasq.net",
        "sub": "identifier",
        "uid": user.id,
        "username": user.username,
        "info": user.info,
        "iat": get_int_from_datetime(datetime.now(timezone.utc)),
        "exp": get_int_from_datetime(
            datetime.now(timezone.utc) + timedelta(weeks=1),
        ),
    }
    with open(signing_key_path, 'rb') as fh:
        signing_key = jwk_from_pem(fh.read())
    return instance.encode(payload, signing_key, alg=settings.SIGNING_ALGORITHM)


class JWTAuthentication(BaseAuthentication):
    keyword = "JWT"
    model = None

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            exceptions.AuthenticationFailed("Authorization invalid")
        elif len(auth) > 2:
            exceptions.AuthenticationFailed("Authorization invalid no space")

        with open(verifying_key_path, 'rb') as fh:
            verifying_key = jwk_from_pem(fh.read())
        try:
            jwt_token = auth[1]
            jwt_info = instance.decode(jwt_token.decode("utf-8"), verifying_key, do_time_check=True)
            uid = jwt_info.get("uid")
            user = UserInfo.objects.get(pk=uid)
            user.is_authenticated = True
            return (user, jwt_token)
        except JWTDecodeError:
            raise exceptions.AuthenticationFailed("Authorization faild token timed out")

    def authenticate_header(self, request):
        pass

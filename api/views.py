from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .utils.auth import JWTAuthentication, NormalAuthentication


class Login(APIView):
    authentication_classes = [NormalAuthentication, ]

    def post(self, request, *args, **kwargs):
        return Response({"token": request.user})


class Something(APIView):
    authentication_classes = [JWTAuthentication, ]
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        return Response({"data": "this is content."})

from django.core.exceptions import ValidationError
from django.shortcuts import render
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserViewSerializer, ProfileSerializer, \
    SocialSerializer, ImageSeriliazer, ChangePasswordSerializer
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView, CreateAPIView, UpdateAPIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from django.conf import settings
from django.contrib.auth import get_user_model
from .utils import generate_access_token
from .models import AppUser, Profile, Social, Image, CustomUri
from datetime import datetime, timedelta
from user_api.customModels import CustomURLField
from django.core import validators
import jwt


class UserRegister(APIView):
    serializer_class = UserRegistrationSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def get(self, request):
        content = {'message': 'Hello!'}
        return Response(content)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            new_user = serializer.save()
            if new_user:
                access_token = generate_access_token(new_user)
                data = {'access_token': access_token}
                response = Response(data, status=status.HTTP_201_CREATED)
                response.set_cookie(key='access_token', value=access_token, httponly=True)
                return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    serializer_class = UserLoginSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def post(self, request):
        username = request.data.get('username', None)
        # email = request.data.get('email', None)
        user_password = request.data.get('password', None)
        user_model = get_user_model()

        if not username:
            raise AuthenticationFailed('A username is needed.')

        if not user_password:
            raise AuthenticationFailed('A user password is needed.')

        """
        if not email:
            raise AuthenticationFailed('An user email is needed.')
        """

        user_instance = authenticate(username=username, password=user_password)

        if not user_instance:
            raise AuthenticationFailed('User not found.')

        if user_instance.is_active:
            user_access_token = generate_access_token(user_instance)
            response = Response()
            response.set_cookie(key='access_token', value=user_access_token, httponly=True)
            response.data = {
                'access_token': user_access_token,
                'user': user_instance.user_id,
            }

            return response
        return Response({
            'message': 'Something went wrong.'
        })


class UserView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def get(self, request):
        user_token = request.COOKIES.get('access_token')

        if not user_token:
            raise AuthenticationFailed('Unauthenticated user.')

        try:
            payload = jwt.decode(user_token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            response = Response()
            response.delete_cookie('access_token')
            response.status_code = 401
            response.data = {
                'message': 'Session is expired.'
            }
            return response

        user_model = get_user_model()
        user = user_model.objects.filter(user_id=payload['user_id']).first()
        user_serializer = UserViewSerializer(user)
        return Response(user_serializer.data)


class UserLogout(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def get(self, request):
        user_token = request.COOKIES.get('access_token', None)
        if user_token:
            response = Response()
            response.delete_cookie('access_token')
            response.data = {
                'message': 'Logged out successfully.'
            }
            return response
        response = Response()
        response.data = {
            'message': 'User is already logged out.'
        }
        return response


class GetUserProfile(ListAPIView):
    permission_classes = (AllowAny,)
    lookup_url_kwarg = "userid"
    serializer_class = ProfileSerializer

    def get_queryset(self):
        uid = self.kwargs[self.lookup_url_kwarg]
        profile = Profile.objects.filter(user=uid).all()
        return profile


class GetUserSocial(ListAPIView):
    permission_classes = (AllowAny,)
    lookup_url_kwarg = "userid"
    serializer_class = SocialSerializer

    def get_queryset(self):
        uid = self.kwargs[self.lookup_url_kwarg]
        social = Social.objects.filter(user=uid).all()
        return social


class GetUser(RetrieveAPIView):
    permission_classes = (AllowAny,)
    lookup_url_kwarg = "userid"
    serializer_class = UserViewSerializer
    user_model = get_user_model()

    def get_object(self):
        uid = self.kwargs[self.lookup_url_kwarg]
        user = self.user_model.objects.filter(user_id=uid).first()
        return user


class AddSocial(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = SocialSerializer
    custom_uri_class = CustomUri

    def post(self, request):

        urlvalidator = validators.URLValidator(schemes=["http", "https", "ftp", "ftps", "mailto", "tel", "bank"])
        tempdict = self.request.POST.copy()
        try:
            # validates url, if it`s not validated then it will save without custom uri.
            urlvalidator(tempdict["url"])
            prefixes = ["http", "https"]

            # Get if it has any custom uri
            uri = self.custom_uri_class.objects.filter(name=tempdict["type"]).first()
            if uri is not None:
                for prefix in prefixes:
                    if prefix in tempdict["url"]:
                        index = tempdict["url"].index(prefix)
                        length = tempdict["url"].count(prefix)
                        new_url = tempdict["url"][index + length:] + uri.uri
                        tempdict["url"] = new_url
        except:

            # Get if it has any custom uri
            uri = self.custom_uri_class.objects.filter(name=tempdict["type"]).first()
            if uri is None:
                raise ValidationError("Invalid Data If you are entering a Link please use ('http://' or 'https://' )",
                                      code="invalid")

            new_url = uri.uri + tempdict["url"]
            tempdict["url"] = new_url

        serializer = self.serializer_class(data=tempdict)

        if serializer.is_valid(raise_exception=True):
            new_content = serializer.save()
            if new_content:
                response = Response(status=status.HTTP_201_CREATED)
                return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetPhoto(RetrieveAPIView):
    permission_classes = AllowAny,
    lookup_url_kwarg = "userid"
    serializer_class = ImageSeriliazer
    model = Image

    def get_object(self):
        uid = self.kwargs[self.lookup_url_kwarg]
        image = self.model.objects.filter(user=uid).first()
        return image


class GetChoices(APIView):
    permission_classes = AllowAny,
    model = Social

    def get(self, request):
        choices = [c[0] for c in self.model.SocialChoices.choices]
        resp = Response()
        resp.status_code = 200
        resp.data = {
            "choices": choices
        }
        return resp


class ChangePassword(UpdateAPIView):
    model = AppUser
    permission_classes = (AllowAny,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = ChangePasswordSerializer
    user_id = None
    object = None

    def get_object(self, queryset=None):
        obj = self.model.objects.filter(user_id=self.user_id).first()
        return obj

    def update(self, request, *args, **kwargs):
        self.user_id = request.data.get("user")
        self.object = self.get_object()
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=True):
            # Check old password
            old_password = serializer.data.get("old_password")
            if not self.object.check_password(old_password):
                return Response({"old_password": ["Wrong password."]},
                                status=status.HTTP_400_BAD_REQUEST)

            # create new access token because of new password
            user_access_token = generate_access_token(
                authenticate(username=self.object.username, password=old_password))

            # Setting new password
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = Response()
            response.set_cookie(key='access_token', value=user_access_token, httponly=True)
            response.status_code = status.HTTP_200_NO_CONTENT
            response.data = {
                "acces_token": user_access_token
            }
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EditDetails(UpdateAPIView, CreateAPIView):
    model = Profile
    uri_model = CustomUri
    user_model = get_user_model()
    serializer_class = ProfileSerializer
    permission_classes = (AllowAny,)
    lookup_url_kwarg = "userid"
    authentication_classes = (TokenAuthentication,)

    response = Response

    def get_object(self, type):
        obj = self.model.objects.filter(user=self.kwargs[self.lookup_url_kwarg], type=type).first()
        return obj

    # request has 3 diffrent row {"Telephone", "Mail", "Pin"}
    def post(self, request, **kwargs):
        # Iteration over all diffrent rows
        for type in request.data:

            # If a type has a custom uri for example 'Telephone' has 'tel://' searches
            uri = self.uri_model.objects.filter(name=type).first()

            # if uri is none url will be blank
            if uri is not None:
                data = {
                    "type": type,
                    "content": request.data[type],
                    "url": uri.uri + request.data[type],
                    "user": self.kwargs[self.lookup_url_kwarg]
                }
            else:
                data = {
                    "type": type,
                    "content": request.data[type],
                    "user": self.kwargs[self.lookup_url_kwarg]
                }

            # Serializing data
            serializer = self.serializer_class(data=data)

            # Gets profile model if already have
            obj = self.get_object(type)

            if serializer.is_valid(raise_exception=True):

                # Checks model is already inserted if inserted then updates data
                if obj is not None:
                    obj.type = serializer.data.get("type")
                    obj.content = serializer.data.get("content")
                    obj.url = serializer.data.get("url")
                    obj.user_id = serializer.data.get("user")
                    print(obj.type, obj.user_id, obj.url, obj.content)
                    obj.save()
                    self.response.status_code = status.HTTP_200_OK
                else:
                    db_instance = self.model(type=serializer.data.get("type"), content=serializer.data.get("content"),
                                             url=serializer.data.get("url"), user_id=serializer.data.get("user"))
                    db_instance.save()
                    self.response.status_code = status.HTTP_201_CREATED

        return self.response

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.template.loader import render_to_string
from rest_framework import status

from . utils import *
from .serializers import *
from .models import *
from .permissions import *

# Create your views here.


class CreateAcountView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = AccountSerializer(data=request.data)
        data = {}

        if serializer.is_valid(raise_exception=False):
            user = serializer.save()
            user.save()
            data["response"] = "Account created successfully"
            data["user_info"] = AccountSerializer(user).data
            data["Token"] = auth_jwt(user)
            return Response(data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        data = {}

        if serializer.is_valid(raise_exception=False):
            email = serializer.validated_data.get("email")
            username = serializer.validated_data.get("username")
            password = serializer.validated_data.get("password")
            if email:
                try:
                    user = Account.objects.get(email=email)
                except Account.DoesNotExist:
                    return Response({"Message": "Email does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            elif username:
                try:
                    user = Account.objects.get(username=username)
                except Account.DoesNotExist:
                    return Response({"Message": "Username does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            if not user.check_password(password):
                return Response({"Message": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST)
            
            data["response"] = "User logged in successfully"
            data["user_info"] = AccountSerializer(user).data
            data["Token"] = auth_jwt(user)
            return Response(data, status=status.HTTP_200_OK)
        
        else:
            data["error"] = serializer.errors
            return Response(data, status=status.HTTP_400_BAD_REQUEST)
        


class InitiatePasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        try:
            user = Account.objects.get(email=email)
        except Account.DoesNotExist:
            data = {"error": "User with this email does not exist"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)
        user.otp = otp_generation()
        user.save()
        
        context = {
            "email": user.email,
            "otp": user.otp,
        }
        try:
            template = render_to_string("initiate_password.html", context)
            send_email(email, "Account: Password Reset", template)
        except Exception as e:
            return Response("Error sending email", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        data = {"response": "OTP sent successfully"}
        return Response(data, status=status.HTTP_200_OK)
    


class SetNewPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializers = SetNewPasswordSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):
            data = serializers.validated_data()
            
            try:
                user = Account.objects.get(otp=data["otp"])
            except Account.DoesNotExist:
                return Response("Invalid OTP", status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(data["password"])
            user.save()
            data = {"response": "Password set successfully"}
            return Response(data, status=status.HTTP_200_OK)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
    


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializers = ChangePasswordSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):
            data = serializers.validated_data()
            
            try:
                user = Account.objects.get(request.user)
            except Account.DoesNotExist:
                return Response("Invalid user", status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(data["password"])
            user.save()
            data = {"response": "Password set successfully"}
            return Response(data, status=status.HTTP_200_OK)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)



class ProfileView(APIView):

    def get(self, request):
        user = request.user
        serializer = ProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request):
        user = request.user
        serializer = ProfileSerializer(user, data=request.data, partial=True)

        if serializer.is_valid(raise_exception=True):
            serializer.save()

            return Response(serializer.data, status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

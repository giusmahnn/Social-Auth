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
<<<<<<< HEAD
    


class GoogleAuthRedirect(APIView):
    def get(self, request):
        redirect_uri = f"https://accounts.google.com/o/oauth2/auth?client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}&response_type=code&scope=https://www.googleapis.com/auth/userinfo.profile%20https://www.googleapis.com/auth/userinfo.email&access_type=offline&redirect_uri=https://ee39-2c0f-f5c0-620-91f6-8078-b676-a78b-dfde.ngrok-free.app/google/callback"
        return redirect(redirect_uri)
    

class GoogleAuthCallback(APIView):
    def get(self, request):
            code = request.GET.get("code")
            if not code:
                return Response({"Error": "Authorization code is missing"}, status=status.HTTP_400_BAD_REQUEST)

            # Exchange the authorization code for an access token
            token_uri = "https://oauth2.googleapis.com/token"
            token_params = {
                "code": code,
                "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
                "client_secret": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
                "redirect_uri": "https://ee39-2c0f-f5c0-620-91f6-8078-b676-a78b-dfde.ngrok-free.app/google/callback",
                "grant_type": "authorization_code",
            }

            token_response = requests.post(token_uri, data=token_params)
            if token_response.status_code != 200:
                return Response(
                    {"Error": "Failed to fetch access token", "details": token_response.json()},
                    status=token_response.status_code
                )

            access_token = token_response.json().get("access_token")
            if not access_token:
                return Response({"Error": "Access token is missing"}, status=status.HTTP_400_BAD_REQUEST)

            # Fetch user profile
            profile_endpoint = "https://www.googleapis.com/oauth2/v1/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            profile_response = requests.get(profile_endpoint, headers=headers)

            if profile_response.status_code != 200:
                return Response(
                    {"Error": "Failed to fetch user profile", "details": profile_response.json()},
                    status=profile_response.status_code
                )

            profile_data = profile_response.json()
            data={}
            # Create or update the user account
            user, created = Account.objects.get_or_create(
                email=profile_data["email"],
                defaults={
                    "first_name": profile_data.get("given_name", ""),
                    "last_name": profile_data.get("family_name", ""),
                    "profile_picture": profile_data.get("picture", ""),
                }
            )

            # Update missing fields for existing users
            if not created:
                updated = False
                if not user.first_name and profile_data.get("given_name"):
                    user.first_name = profile_data["given_name"]
                    updated = True
                if not user.last_name and profile_data.get("family_name"):
                    user.last_name = profile_data["family_name"]
                    updated = True
                if not user.profile_picture and profile_data.get("picture"):
                    user.profile_picture = profile_data["picture"]
                    updated = True
                if updated:
                    user.save()

            # Prepare response
            serializer = AccountSerializer(user)
            refresh = RefreshToken.for_user(user)

            data["message"] = "User Created Successfully" if created else "User Logged in successfully"
            data["user_details"] = serializer.data
            data['access'] = str(refresh.access_token)
            data['refresh'] = str(refresh)
            return Response(data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)




            
=======
>>>>>>> parent of b55baa5 (google social login set up)

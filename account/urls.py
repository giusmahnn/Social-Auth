from django.urls import path
from .views import *


urlpatterns = [
    path("signup/", CreateAcountView.as_view()),
    path("login/", LoginView.as_view()),
    path("profile/", ProfileView.as_view()),
    path("set-new-password/", SetNewPasswordView.as_view()),
    path("change-password/", ChangePasswordView.as_view())
]
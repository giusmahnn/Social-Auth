import datetime
import re
from django.forms import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
import random

from account.models import Account



def otp_generation(*, k=6):
    """
    Function to generate a random OTP (One Time Password).

    Parameters:
    k (int): Length of the OTP. Default value is 6.

    Returns:
    str: A random string of length k containing digits.
    """
    return ''.join(random.choices('0123456789', k=k))


def auth_jwt(user):
    """
    Function to authenticate a user using JWT (JSON Web Tokens).

    Parameters:
    user (User): The user to be authenticated.

    Returns:
    dict: A dictionary containing the JWT access token and refresh token.
    """
    refresh_token = RefreshToken.for_user(user)
    access_token = refresh_token.access_token
    return {
        'access_token': str(access_token),
        'refresh_token': str(refresh_token)
    }



def send_email(user_email, subject, template):
    """
    Function to send an email with a randomly generated OTP.

    Parameters:
    user_email (str): The email address of the recipient.
    subject (str): The subject line of the email.
    template (str): The name of the email template file.
    """
    subject = subject
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user_email]

    email = EmailMultiAlternatives(
        subject=subject,
        body="email content",
        from_email=from_email,
        to=recipient_list,
    )
    email.content_subtype = "html"
    email.attach_alternative(template, "text/html")

    try:
        email.send(fail_silently=False)
    except Exception as e:
        print("Error sending email", {'message':{e}})
        return "Couldn't send email"
    
    return None


def validate_otp(user_email, otp, ttl_minutes=5):
    """
    Function to validate the OTP sent to the user's email.

    Parameters:
    user_email (str): The email address of the user.
    otp (str): The OTP entered by the user.
    ttl_minutes (int): The time-to-live (TTL) for the OTP in minutes. Default value is 5.

    Returns:
    bool: True if the OTP is valid, False otherwise.
    """
    try:
        user = Account.objects.filter(email=user_email).first()
    except Account.DoesNotExist:
        return False
    
    if not user.otp or not user.otp_created_at or datetime.timezone.now() > datetime.timedelta(minutes=ttl_minutes):
        user.reset_otp()
        return "The OTP has expired, please request a new one."  # OTP expired

    if user.otp == otp:
        user.reset_otp()
        return "OTP validated successfully"
    return "Invalid OTP"


def validate_password(value):
    """
    Function to validate the password.

    Parameters:
    value (str): The password entered by the user.

    Returns:
    bool: True if the password meets the criteria, False otherwise.
    """
    if len(value) < 8:
        raise ValidationError(
            "Password must be at least 8 characters long")
    if not any(char.isdigit() for char in value):
        raise ValidationError(
            "Password must contain at least one digit")
    if not any(char.isalpha() for char in value):
        raise ValidationError(
            "Password must contain at least one letter")
    if not any(char.islower() for char in value):
        raise ValidationError(
            "Password must contain at least one lowercase letter")
    if not any(char.isupper() for char in value):
        raise ValidationError(
            "Password must contain at least one uppercase letter")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
        raise ValidationError(
            "Password must contain at least one special character")
    return value
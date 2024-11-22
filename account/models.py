import datetime
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from .choices import *
# Create your models here.


class AccountManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email must be provided")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        user = self.create_user(email, password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
    


class Account(AbstractUser):
    first_name = models.CharField(max_length=26, blank=True, null=True)
    last_name = models.CharField(max_length=26, blank=True, null=True)
    profile_picture = models.ImageField(
        upload_to="profile_images/", default="profile_images/default-profile-image.png", blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    date_of_birth = models.DateField(null=True, blank=True)
    age = models.IntegerField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=Gender.choices, null=True, blank=True)
    username = models.CharField(max_length=26, null=True, blank=True, unique=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)


    objects = AccountManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def cal_age(self):
        # Calculate the age based on the date of birth, if available
        if not self.date_of_birth:
            return None
        today = datetime.date.today()
        age = today.year - self.date_of_birth.year
        if today.month < self.date_of_birth.month or (today.month == self.date_of_birth.month and today.day < self.date_of_birth.day):
            age -= 1
        return age
    
    def save(self, *args, **kwargs):
        # Calculate the age based on the date of birth, if available and update the age field accordingly
        if self.date_of_birth:
            self.age = self.cal_age()
        super().save(*args, **kwargs)

    def reset_otp(self):
        # Reset the otp field to the default
        self.otp = None
        self.otp_created_at = None
        self.save(update_fields=["otp", "otp_created_at"])

    def __str__(self):
        return f"{self.first_name or ''} {self.last_name or ''}".strip()
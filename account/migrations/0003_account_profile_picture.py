# Generated by Django 5.1.3 on 2024-11-22 12:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_account_otp_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='profile_picture',
            field=models.ImageField(blank=True, default='profile_images/default-profile-image.png', null=True, upload_to='profile_images/'),
        ),
    ]

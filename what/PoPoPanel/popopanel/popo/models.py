"""
This file is part of POPOPANEL.

@package     POPOPANEL is part of WHAT PANEL – Web Hosting Application Terminal Panel.
@copyright   2023-2024 Version Next Technologies and MadPopo. All rights reserved.
@license     BSL; see LICENSE.txt
@link        https://www.version-next.com
"""
from django.db import models
class test(models.Model):
    full_name = models.CharField(max_length=100)
    password = models.CharField(max_length=100)

    def __str__(self):
        return self.full_name


class Customer(models.Model):
    full_name = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    email = models.EmailField()
    address1 = models.CharField(max_length=255)
    address2 = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)

    def __str__(self):
        return self.full_name

class Website(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    website_name = models.CharField(max_length=100)
    ftp_username = models.CharField(max_length=100)
    ftp_password = models.CharField(max_length=100)
    php_version = models.CharField(max_length=10)
    database_allowed = models.IntegerField()

    def __str__(self):
        return self.website_name

class Subdomain(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE) 
    subdomain_name = models.CharField(max_length=255)
    php_version = models.CharField(max_length=10)
    subdomainftpuser = models.CharField(max_length=255, default='')  # Added field for FTP username
    subdomainftppass = models.CharField(max_length=255, default='')

    def __str__(self):
        return self.subdomain_name

# models.py
class Database(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    user = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class WordPressCredentials(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE)
    wp_username = models.CharField(max_length=255)
    wp_password = models.CharField(max_length=255)
    wp_database_name = models.CharField(max_length=255)
    wp_database_user = models.CharField(max_length=255)
    wp_database_pass = models.CharField(max_length=255)

    def __str__(self):
        return self.wp_username


# dj/models.py

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

class UserManager(BaseUserManager):
    def create_user(self, username, emailid, password=None):
        if not username:
            raise ValueError('The Username field is required')
        if not emailid:
            raise ValueError('The Email field is required')

        user = self.model(username=username, emailid=emailid)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, emailid, password=None):
        user = self.create_user(username, emailid, password)
        user.is_admin = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    username = models.CharField(max_length=100, unique=True)
    emailid = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # AbstractBaseUser includes password hashing
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['emailid']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin


class Dbuserpass(models.Model):
    ftp_username = models.CharField(max_length=100)
    website_name = models.CharField(max_length=100)
    db_name = models.CharField(max_length=100)
    db_user = models.CharField(max_length=100)
    db_pass = models.CharField(max_length=100)



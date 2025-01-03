"""
This file is part of POPOPANEL.

@package     POPOPANEL is part of WHAT PANEL – Web Hosting Application Terminal Panel.
@copyright   2023-2024 Version Next Technologies and MadPopo. All rights reserved.
@license     BSL; see LICENSE.txt
@link        https://www.version-next.com
"""

from pathlib import Path
import os 

# settings.py
LOGIN_URL = '/login/'  # Adjust this to the correct path for your login view


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


TEM_DIR = os.path.join(BASE_DIR,'popo/templates')

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-g9l&9arlex3^*4^*2ekj0iz1#v^udo$5tr*ru_la312dr8!!$g'

# SECURITY WARNING: don't run with debug turned on in production!   
DEBUG = True

ALLOWED_HOSTS = ['localhost','127.0.0.1','192.168.3.239','94.136.186.0']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'popo',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'popo.middleware.RedirectAuthenticatedUserMiddleware',
]

ROOT_URLCONF = 'popopanel.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [TEM_DIR],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.csrf',
            ],
        },
    },
]

WSGI_APPLICATION = 'popopanel.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

# DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': BASE_DIR / '/var/www/html/popopanel/djangoproject/db.sqlite3',
#        'USER': 'sahil',
#        'PASSWORD':'sahilrashmit',
#        'HOST':'localhost',
#        'PORT':'3306',
#    }
# }

# mysql username- root ,passwd- sahil00 

# Database Credentials
# DATABASES = {

#      'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'popo',
#         'USER': 'sahil',
#         'PASSWORD': 'rashmit@123',
#         'HOST': 'localhost',  
#         'PORT': '3306',
#      }
#  }

# Database Credentials end 
 
# ssl live server
# DATABASES = {

#      'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'popo',
#         'USER': 'rashmit',
#         'PASSWORD': 'rash',
#         'HOST': 'localhost',  # You can change this if your MySQL server is hosted elsewhere
#         'PORT': '3306',
#      }
#  }


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTH_USER_MODEL = 'popo.User'
AUTHENTICATION_BACKENDS = [
    'popo.auth_backends.CustomBackend',
    'popo.auth_backends.CustomerBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# settings.py
SESSION_COOKIE_AGE = 1209600  # Two weeks in seconds
SESSION_SAVE_EVERY_REQUEST = True  # Save the session to the database on every request
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # Use database for session storage



# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'popo/static'),
]

STATIC_ROOT = '/var/www/html/popopanel/popopanel/static/'
# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
STATIC_ROOT = '/var/www/html/popopanel/popopanel/static/'
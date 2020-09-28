from django.db import models
import re
import bcrypt
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


# Create your models here.
class UserManager(models.Manager):
    def reg_validator(self, postData):
        errors = {}
        if len(postData['first_name']) == 0:
            errors['first_name'] = "Must include First Name"
        elif len(postData['first_name']) < 2 or postData['first_name'].isalpha() != True:
            errors['first_name'] = "First name must be at least 2 characters, and letters only"
        if len(postData['last_name']) == 0:
            errors['last_name'] = "Must include Last Name"
        elif len(postData['last_name']) < 2 or postData['last_name'].isalpha() != True:
            errors['last_name'] = "Last name must be at least 2 characters, and letters only"
        if len(postData['email']) == 0:
            errors['email'] = "Must inclue email"
        elif not email_regex.match(postData['email']):
            errors['email'] ="Invalid email"
        
        email_check = User.objects.filter(email=postData['email'])
        if len(email_check) != 0:
            errors['email'] = "Email already exists"
        if len(postData['password']) ==0:
            errors['password'] = "Password required"
        elif len(postData['password']) < 8:
            errors['password'] = "Password must be at least 8 characters"
        elif postData['password'] != postData['confirm_pw']:
            errors['password'] = "Password and Confirmed Password do not match"
        return errors
    



    def log_validator(self, postData):
        errors = {}
        if len(postData['email']) == 0:
            errors['email'] = "Must inclue email"
        elif not email_regex.match(postData['email']):
            errors['email'] ="Invalid email"
        existing_user = User.objects.filter(email=postData['email'])
        if len(existing_user) == 0:
            errors['email'] = "User not found"
        if len(postData['password']) ==0:
            errors['password'] = "Password required"
        elif len(postData['password']) < 8:
            errors['password'] = "Password must be at least 8 characters"
        if len(existing_user) == 1:
            if bcrypt.checkpw(postData['password'].encode(),existing_user[0].password.encode()) != True:
                errors['email'] = "Email and password do not match"
        
        return errors





class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
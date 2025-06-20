from django.db import models

class User(models.Model):
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    
    # Optional fields
    phone = models.CharField(max_length=20, blank=True, null=True)
    type_flag = models.CharField(max_length=20, blank=True, null=True)
    dob = models.DateField(blank=True, null=True)  # Date of Birth
    nationality = models.CharField(max_length=100, blank=True, null=True)
    gender = models.CharField(max_length=10, choices=[("male", "Male"), ("female", "Female"), ("other", "Other")], blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    google_id = models.CharField(max_length=255, blank=True, null=True)
    facebook_id = models.CharField(max_length=255, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=64, blank=True, null=True)
    verification_token_created_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.email

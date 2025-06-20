from django.db import models
from django.utils import timezone

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

class LoginSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    access_token = models.TextField()
    refresh_token = models.TextField()
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    email = models.EmailField(unique=True)

    def __str__(self):
        return f"{self.user.email} - {self.login_time}"

class OTPAttempt(models.Model):
    email = models.EmailField(unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    attempts = models.IntegerField(default=1)

    def __str__(self):
        return f"{self.email} - {self.attempts} attempts at {self.timestamp}"
class PasswordResetOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=10)  # expires in 10 mins

    def __str__(self):
        return f"{self.email} - {self.otp}"
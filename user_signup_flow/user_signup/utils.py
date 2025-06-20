import os
import httpx
from django.core.mail import EmailMessage
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User
from .serializers import UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache
import random
from datetime import timedelta
from django.utils import timezone
from .models import *


MAX_OTP_ATTEMPTS = 3
OTP_ATTEMPT_WINDOW = 3600  # 1 hour

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
BREVO_SENDER_NAME = os.getenv("BREVO_SENDER_NAME")

async def send_email_via_brevo(email: str, body: str, subject: str, name: str = "") -> dict:
    """Send email using Brevo API asynchronously."""

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }

    recipient = {"email": email}
    if name:
        recipient["name"] = name

    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": SENDER_EMAIL},
        "to": [recipient],
        "subject": subject,
        "htmlContent": body,
    }

    BREVO_EMAIL_HOST = os.getenv("BREVO_EMAIL_HOST")  

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(BREVO_EMAIL_HOST, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        send_email_via_django(email, subject, body)
        return {"status": "fallback", "error": str(e)}

def send_email_via_django(email: str, subject: str, html_content: str):
    """Fallback email sender using Django's SMTP backend."""
    try:
        msg = EmailMessage(subject, html_content, from_email= SENDER_EMAIL, to=[email])
        msg.content_subtype = "html"
        msg.send()
    except Exception as e:
        raise Exception(f"Failed to send email via Django: {str(e)}")
    
def handle_social_login_signup(self, type_flag, social_id, email, data):
    if type_flag not in ["google", "facebook"]:
        return Response({"error": "Invalid social media type"}, status=400)

    filter_field = f"{type_flag}_id"
    user = User.objects.filter(**{filter_field: social_id}).first()

    if not user and email:
        user = User.objects.filter(email=email).first()
        if user:
            setattr(user, filter_field, social_id)
            user.is_verified = True
            user.save()

    if not user:
        data[filter_field] = social_id
        data["is_verified"] = True
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
        else:
            return Response(serializer.errors, status=400)

    return self.generate_token_response(user, "Social login/signup successful")

def generate_token_response(self, user, message):
    refresh = RefreshToken.for_user(user)
    return Response({
        "message": message,
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh)
    })


def generate_otp():
    return str(random.randint(100000, 999999))

def save_otp_to_db(email, otp):
    PasswordResetOTP.objects.update_or_create(
        email=email,
        defaults={"otp": otp, "created_at": timezone.now()}
    )


def save_otp_to_cache(email, otp):
    cache.set(f"otp_{email}", otp, timeout=600)  # 10 mins

def verify_otp_from_db(email, otp):
    try:
        record = PasswordResetOTP.objects.get(email=email)
        return record.otp == otp and not record.is_expired()
    except PasswordResetOTP.DoesNotExist:
        return False


def has_exceeded_otp_limit(email):
    try:
        attempt = OTPAttempt.objects.get(email=email)
    except OTPAttempt.DoesNotExist:
        return False  # No attempts yet

    time_threshold = timezone.now() - timedelta(seconds=OTP_ATTEMPT_WINDOW)

    # Check if within the cooldown window AND attempts exceed max allowed
    if attempt.timestamp >= time_threshold and attempt.attempts >= MAX_OTP_ATTEMPTS:
        return True

    # If outside window, reset attempts count
    if attempt.timestamp < time_threshold:
        attempt.attempts = 0
        attempt.save()

    return False

def record_otp_attempt(email):
    obj, created = OTPAttempt.objects.get_or_create(email=email)
    if not created:
        obj.attempts += 1
    obj.save()  

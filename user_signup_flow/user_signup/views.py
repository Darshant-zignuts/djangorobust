from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import make_password, check_password
from .models import User
from .serializers import UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
import os
from django.utils.crypto import get_random_string
from .utils import *
import asyncio
from django.utils import timezone
from datetime import timedelta
from jwt import ExpiredSignatureError, InvalidTokenError, decode
from django.utils.timezone import now
from django.conf import settings

VERIFICATION_TOKEN_EXPIRY_HOURS = 120  

class SignupLoginAPIView(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')
        type_flag = data.get('type_flag')  
        social_media_id = data.get('social_media_id')
        if type_flag and social_media_id:
            resp = self.handle_social_login_signup(type_flag, social_media_id, email, data)
            if resp is None:
                return Response({"error": "Social login/signup handler returned no response"}, status=500)
            return resp
            # return self.handle_social_login_signup(type_flag, social_media_id, email, data)
        if not email and not password:
            return Response({"error": "Email and password are required."}, status=400)
        elif not email:
            return Response({"error": "Email is required."}, status=400)
        elif not password:
            return Response({"error": "Password is required."}, status=400)
        
        try:
            print("came inside first try")
            user = User.objects.get(email=email)

            if user.is_active and not check_password(password, user.password):
                return Response({"error": "Invalid password"}, status=401)
            elif user.is_active and check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                serializer = UserSerializer(user)
                return Response({"message": "Login successful",  "access_token": str(refresh.access_token), "refresh_token": str(refresh)}, status=200)
            elif not user.is_active:
                if user.verification_token_created_at is None:
                    print("Came inside token created at is none")
                    token_expired = True
                else:
                    print("came inside else token expired")
                    token_age = timezone.now() - user.verification_token_created_at
                    token_expired = token_age > timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)

                print("came inside token expired")
                # Generate new token and send verification email
                verification_token = get_random_string(length=32)
                user.verification_token = verification_token
                user.verification_token_created_at = timezone.now()
                user.save()

                verification_link_base = os.getenv('EMAIL_VERIFICATION_URL')
                verification_link = f"{verification_link_base}{verification_token}/"
                print("came before sending emi")
                html_content = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="max-width: 600px; margin: auto; background: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);">
                    <h2 style="color: #333333;">Hello {user.full_name},</h2>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        We're excited to have you on board! To get started, please verify your email address by clicking the button below.
                    </p>

                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" style="display: inline-block; padding: 14px 28px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 16px;">
                        Verify Your Email
                        </a>
                    </div>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        If the button doesn't work, you can copy and paste the following link into your browser:
                    </p>

                    <p style="word-break: break-all; color: #4CAF50; font-size: 14px;">
                        <a href="{verification_link}" style="color: #4CAF50;">{verification_link}</a>
                    </p>

                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #dddddd;" />

                    <p style="color: #888888; font-size: 13px;">
                        Didn't request this email? No problem — just ignore it.
                    </p>

                    <p style="color: #555555; font-size: 15px;">
                        Best regards,<br/>
                        The Support Team
                    </p>
                    </div>
                </body>
                </html>
                """

                subject = "Verify your email"
                brevo_api_key = os.getenv("BREVO_API_KEY")

                if brevo_api_key:
                    try:
                        asyncio.run(send_email_via_brevo(
                            email=user.email,
                            body=html_content,
                            subject=subject,
                            name=user.full_name
                        ))
                    except Exception as e:
                        send_email_via_django(email, subject, html_content)
                        return Response({"error": "Failed to send verification email via Brevo", "details": str(e)}, status=500)
                else:
                    try:
                        send_email_via_django(
                            email=user.email,
                            subject=subject,
                            html_content=html_content
                        )
                    except Exception as e:
                        return Response({"error": "Failed to send verification email", "details": str(e)}, status=500)
                    
                return Response({"message": "Account not verified. A new verification link has been sent to your email."}, status=403)


        except User.DoesNotExist:
            print("came inside user does not exist")
            # Signup Flow
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                user = serializer.save(is_active=False)  # make user inactive until verified
                verification_token = get_random_string(length=32)
                user.verification_token = verification_token
                user.verification_token_created_at = timezone.now()
                user.save()

                verification_link_base = os.getenv('EMAIL_VERIFICATION_URL')
                verification_link = f"{verification_link_base}{verification_token}/"

                html_content = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="max-width: 600px; margin: auto; background: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);">
                    <h2 style="color: #333333;">Hello {user.full_name},</h2>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        We're excited to have you on board! To get started, please verify your email address by clicking the button below.
                    </p>

                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" style="display: inline-block; padding: 14px 28px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 16px;">
                        Verify Your Email
                        </a>
                    </div>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        If the button doesn't work, you can copy and paste the following link into your browser:
                    </p>

                    <p style="word-break: break-all; color: #4CAF50; font-size: 14px;">
                        <a href="{verification_link}" style="color: #4CAF50;">{verification_link}</a>
                    </p>

                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #dddddd;" />

                    <p style="color: #888888; font-size: 13px;">
                        Didn't request this email? No problem — just ignore it.
                    </p>

                    <p style="color: #555555; font-size: 15px;">
                        Best regards,<br/>
                        The Support Team
                    </p>
                    </div>
                </body>
                </html>
                """

                subject = "Verify your email"
                brevo_api_key = os.getenv("BREVO_API_KEY")

                if brevo_api_key:
                    try:
                        asyncio.run(send_email_via_brevo(
                            email=user.email,
                            body=html_content,
                            subject=subject,
                            name=user.full_name
                        ))
                        print("came inside try of sending email via Brevo")
                    except Exception as e:
                        print("came inside except of sending email via Brevo")
                        send_email_via_django(email, subject, html_content)
                        return Response({"error": "Failed to send verification email via Brevo", "details": str(e)}, status=500)
                else:
                    try:
                        print("came inside try of sending email via django")
                        send_email_via_django(
                            email=user.email,
                            subject=subject,
                            html_content=html_content
                        )
                    except Exception as e:
                        print("came inside except of sending email via django")
                        return Response({"error": "Failed to send verification email", "details": str(e)}, status=500)

                return Response({"message": "Signup successful. Please check your email to verify your account."}, status=201)

            return Response(serializer.errors, status=400)
        return Response({"error": "Unexpected error. No response returned."}, status=500)

# Logout View
class LogoutAPIView(APIView):
    def post(self, request):
        request.session.flush()  
        return Response({
            "message": "Logout successful",
            "redirect_url": "/signin/"  
        }, status=200)


class ForgotPasswordRequestOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=404)

        otp = generate_otp()
        save_otp_to_cache(email, otp)

        html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);">
                    <h2 style="color: #333333;">Hello {user.full_name},</h2>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        You requested to reset your password. Use the following One-Time Password (OTP) to proceed:
                    </p>

                    <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #1a73e8; margin: 20px 0; text-align: center;">
                        {otp}
                    </p>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        This OTP will expire in 10 minutes. If you did not request a password reset, please ignore this email.
                    </p>

                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #dddddd;" />

                    <p style="color: #555555; font-size: 15px;">
                        Best regards,<br/>
                        The Support Team
                    </p>
                </div>
            </body>
            </html>
            """


        subject = "Verify your email"
        brevo_api_key = os.getenv("BREVO_API_KEY")

        if brevo_api_key:
            try:
                asyncio.run(send_email_via_brevo(
                    email=user.email,
                    body=html_content,
                    subject=subject,
                    name=user.full_name
                ))
            except Exception as e:
                send_email_via_django(email, subject, html_content)
                return Response({"error": "Failed to send verification email via Brevo", "details": str(e)}, status=500)
        else:
            try:
                send_email_via_django(
                    email=user.email,
                    subject=subject,
                    html_content=html_content
                )
            except Exception as e:
                return Response({"error": "Failed to send verification email", "details": str(e)}, status=500)

        return Response({"message": "OTP sent to your email."}, status=200)



class ForgotPasswordResetAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")

        if not email or not otp or not new_password:
            return Response({"error": "Email, OTP, and new password are required."}, status=400)

        if not verify_otp_from_cache(email, otp):
            return Response({"error": "Invalid or expired OTP."}, status=400)

        try:
            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()
            # Optionally clear OTP from cache
            cache.delete(f"otp_{email}")
            return Response({"message": "Password reset successful. You can now login."}, status=200)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=404)


class RequestPasswordResetOTP(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=404)

        otp = generate_otp()
        save_otp_to_cache(email, otp)
        html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);">
                    <h2 style="color: #333333;">Hello {user.full_name},</h2>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        You requested to reset your password. Use the following One-Time Password (OTP) to proceed:
                    </p>

                    <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #1a73e8; margin: 20px 0; text-align: center;">
                        {otp}
                    </p>

                    <p style="color: #555555; font-size: 15px; line-height: 1.6;">
                        This OTP will expire in 10 minutes. If you did not request a password reset, please ignore this email.
                    </p>

                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #dddddd;" />

                    <p style="color: #555555; font-size: 15px;">
                        Best regards,<br/>
                        The Support Team
                    </p>
                </div>
            </body>
            </html>
            """


        subject = "Verify your email"
        brevo_api_key = os.getenv("BREVO_API_KEY")

        if brevo_api_key:
            try:
                asyncio.run(send_email_via_brevo(
                    email=user.email,
                    body=html_content,
                    subject=subject,
                    name=user.full_name
                ))
            except Exception as e:
                send_email_via_django(email, subject, html_content)
                return Response({"error": "Failed to send verification email via Brevo", "details": str(e)}, status=500)
        else:
            try:
                send_email_via_django(
                    email=user.email,
                    subject=subject,
                    html_content=html_content
                )
            except Exception as e:
                return Response({"error": "Failed to send verification email", "details": str(e)}, status=500)
        return Response({"message": "OTP sent to your email."}, status=200)


class ResetPasswordWithOTP(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")

        if not email or not otp or not new_password:
            return Response({"error": "Email, OTP, and new password are required."}, status=400)

        if not verify_otp_from_cache(email, otp):
            return Response({"error": "Invalid or expired OTP."}, status=400)

        try:
            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()
            # Optional: Clear OTP from cache after successful reset
            cache.delete(f"otp_{email}")
            return Response({"message": "Password reset successful. Please login."}, status=200)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=404)


class VerifyEmailAPIView(APIView):
    def get(self, request):
        token = request.query_params.get('token')
        email = request.query_params.get('email')

        try:
            payload = decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("sub")

            if not user_id:
                return Response({"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(id=user_id, email=email)
            except User.DoesNotExist:
                return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if user.is_active:
                return Response({"message": "User is already Verified. Please login."}, status=status.HTTP_201_CREATED)

            user.is_active = True
            user.updated_at = now()
            user.save()

            return Response({"message": "Email Verified Successfully. Please login."}, status=status.HTTP_200_OK)

        except ExpiredSignatureError:
            return Response({
                "message": "Verification link expired. Please sign up again to receive a new link."
            }, status=status.HTTP_400_BAD_REQUEST)

        except InvalidTokenError:
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


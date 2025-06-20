from django.urls import path
from .views import *

urlpatterns = [
    path('signin/', SignupLoginAPIView.as_view(), name='signup-login'),
    path('signout/', LogoutAPIView.as_view(),name='logout'),
    path('forgot-password/request-otp/', ForgotPasswordRequestOTPAPIView.as_view(), name='forgot-password-request-otp'),
    path('forgot-password/reset/', ForgotPasswordResetAPIView.as_view(), name='forgot-password-reset'),
    path('verify-email/<str:token>/', VerifyEmailAPIView.as_view(), name='verify-email'),
]


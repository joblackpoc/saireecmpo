"""
URL configuration for accounts app.
Includes authentication, registration, and 2FA endpoints.
"""

from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView

from . import views

app_name = 'accounts'

urlpatterns = [
    # Registration
    path('register/', 
         views.UserRegistrationView.as_view(), 
         name='register'),
    
    path('register/complete/', 
         TemplateView.as_view(
             template_name='accounts/registration_complete.html'
         ), 
         name='registration_complete'),
    
    # Email Verification
    path('verify/<str:token>/', 
         views.EmailVerificationView.as_view(), 
         name='verify_email'),
    
    path('verify/resend/', 
         views.ResendVerificationView.as_view(), 
         name='resend_verification'),
    
    # Login/Logout (using 2FA views)
    path('login/', 
         views.SecureLoginView.as_view(), 
         name='login'),
    
    path('logout/', 
         views.logout_view, 
         name='logout'),
    
    # Password Reset
    path('password-reset/', 
         views.PasswordResetView.as_view(), 
         name='password_reset'),
    
    path('password-reset/done/', 
         TemplateView.as_view(
             template_name='accounts/password_reset_done.html'
         ), 
         name='password_reset_done'),
    
    path('password-reset/<str:token>/', 
         views.PasswordResetConfirmView.as_view(), 
         name='password_reset_confirm'),
    
    path('password-reset/complete/', 
         TemplateView.as_view(
             template_name='accounts/password_reset_complete.html'
         ), 
         name='password_reset_complete'),
    
    # Password Change (for logged-in users)
    path('password-change/', 
         views.change_password_view, 
         name='change_password'),
    
    # Two-Factor Authentication
    path('two-factor/setup/', 
         views.TwoFactorSetupView.as_view(), 
         name='two_factor_setup'),
    
    path('two-factor/backup-codes/', 
         views.two_factor_backup_codes, 
         name='two_factor_backup'),
    
    path('two-factor/qr-code/', 
         views.two_factor_qr_code, 
         name='two_factor_qr'),
    
    # Profile Management
    path('profile/', 
         TemplateView.as_view(
             template_name='accounts/profile.html'
         ), 
         name='profile'),
    
    path('profile/edit/', 
         TemplateView.as_view(
             template_name='accounts/profile_edit.html'
         ), 
         name='profile_edit'),
    
    # Security Settings
    path('security/', 
         TemplateView.as_view(
             template_name='accounts/security_settings.html'
         ), 
         name='security_settings'),
    
    # Account Deletion (GDPR compliance)
    path('delete/', 
         TemplateView.as_view(
             template_name='accounts/account_delete.html'
         ), 
         name='account_delete'),
    
    path('delete/confirm/', 
         TemplateView.as_view(
             template_name='accounts/account_delete_confirm.html'
         ), 
         name='account_delete_confirm'),
]
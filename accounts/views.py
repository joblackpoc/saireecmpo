"""
Views for user authentication, registration, and account management.
Includes 2FA setup, email verification, and security features.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils.html import strip_tags
from django.utils import timezone
from django.urls import reverse_lazy, reverse
from django.views import View
from django.views.generic import FormView, TemplateView, UpdateView
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.http import HttpResponse, JsonResponse, Http404
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from two_factor.views import SetupView as TwoFactorSetupView
from two_factor.views.core import LoginView as TwoFactorLoginView
import qrcode
import io
import base64

from .models import EmailUser, EmailVerificationToken, PasswordResetToken, SecurityAuditLog
from .forms import (
    UserRegistrationForm, SecureLoginForm, SecurePasswordResetForm,
    SecureSetPasswordForm, SecurePasswordChangeForm
)


# Decorators for common security patterns
def ratelimit_auth(view_func):
    """Rate limit authentication endpoints."""
    return ratelimit(key='ip', rate='10/h', method='POST')(view_func)


def audit_log(action):
    """Decorator to add audit logging to views."""
    def decorator(view_func):
        def wrapped_view(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            
            # Log the action
            if request.user.is_authenticated:
                SecurityAuditLog.objects.create(
                    user=request.user,
                    action=action,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
                )
            
            return response
        return wrapped_view
    return decorator


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class UserRegistrationView(FormView):
    """
    User registration with email verification.
    Includes CAPTCHA and rate limiting for security.
    """
    template_name = 'accounts/register.html'
    form_class = UserRegistrationForm
    success_url = reverse_lazy('accounts:registration_complete')
    
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    @method_decorator(sensitive_post_parameters('password1', 'password2'))
    @method_decorator(ratelimit(key='ip', rate='5/h', method='POST'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def form_valid(self, form):
        """Save user and send verification email."""
        # Save user with inactive status
        user = form.save(commit=True, request=self.request)
        
        # Create verification token
        token = EmailVerificationToken.objects.create(user=user)
        
        # Send verification email
        self.send_verification_email(user, token)
        
        messages.success(
            self.request,
            'Registration successful! Please check your email to verify your account.'
        )
        
        return super().form_valid(form)
    
    def form_invalid(self, form):
        """Handle invalid form with security logging."""
        # Log suspicious activity if honeypot triggered
        if 'username' in form.errors:
            SecurityAuditLog.objects.create(
                action='SUSPICIOUS_ACTIVITY',
                ip_address=get_client_ip(self.request),
                user_agent=self.request.META.get('HTTP_USER_AGENT', '')[:255],
                details={'type': 'registration_honeypot'}
            )
        
        return super().form_invalid(form)
    
    def send_verification_email(self, user, token):
        """Send email verification link."""
        subject = 'Verify your SecureCMS account'
        
        # Build verification URL
        verification_url = self.request.build_absolute_uri(
            reverse('accounts:verify_email', kwargs={'token': token.token})
        )
        
        # Render email content
        html_message = render_to_string('accounts/emails/verify_email.html', {
            'user': user,
            'verification_url': verification_url,
            'expiry_hours': 24,
        })
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )


class EmailVerificationView(View):
    """
    Email verification endpoint.
    Validates token and activates user account.
    """
    
    @method_decorator(never_cache)
    @method_decorator(ratelimit(key='ip', rate='10/h'))
    def get(self, request, token):
        """Verify email with token."""
        try:
            # Get token
            verification_token = EmailVerificationToken.objects.get(
                token=token,
                is_used=False
            )
            
            # Check expiration
            if verification_token.is_expired():
                messages.error(
                    request,
                    'This verification link has expired. Please request a new one.'
                )
                return redirect('accounts:resend_verification')
            
            # Activate user
            verification_token.use()
            
            # Log verification
            SecurityAuditLog.objects.create(
                user=verification_token.user,
                action='EMAIL_VERIFIED',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
            )
            
            messages.success(
                request,
                'Email verified successfully! You can now log in to your account.'
            )
            return redirect('two_factor:login')
            
        except EmailVerificationToken.DoesNotExist:
            messages.error(
                request,
                'Invalid verification link. Please request a new one.'
            )
            return redirect('accounts:resend_verification')


class ResendVerificationView(FormView):
    """Resend email verification link."""
    template_name = 'accounts/resend_verification.html'
    success_url = reverse_lazy('accounts:registration_complete')
    
    @method_decorator(ratelimit(key='ip', rate='3/h', method='POST'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def get_form(self):
        """Simple email form."""
        from django import forms
        
        class ResendForm(forms.Form):
            email = forms.EmailField(
                label='Email Address',
                widget=forms.EmailInput(attrs={
                    'class': 'form-control',
                    'placeholder': 'your.email@example.com'
                })
            )
        
        return ResendForm(**self.get_form_kwargs())
    
    def form_valid(self, form):
        """Resend verification email if user exists."""
        email = form.cleaned_data['email']
        
        try:
            user = EmailUser.objects.get(email__iexact=email, email_verified=False)
            
            # Invalidate old tokens
            EmailVerificationToken.objects.filter(user=user, is_used=False).update(is_used=True)
            
            # Create new token
            token = EmailVerificationToken.objects.create(user=user)
            
            # Send email
            UserRegistrationView().send_verification_email(user, token)
            
            messages.success(
                self.request,
                'Verification email sent! Please check your inbox.'
            )
            
        except EmailUser.DoesNotExist:
            # Don't reveal if email exists
            messages.success(
                self.request,
                'If an unverified account exists with this email, a verification link has been sent.'
            )
        
        return super().form_valid(form)


class SecureLoginView(TwoFactorLoginView):
    """
    Enhanced login view with 2FA support.
    Includes rate limiting and security logging.
    """
    template_name = 'accounts/login.html'
    form_class = SecureLoginForm
    success_url = reverse_lazy('dashboard')
    
    @method_decorator(sensitive_post_parameters('password'))
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    @method_decorator(ratelimit(key='ip', rate='10/h', method='POST'))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        """Handle successful login with security checks."""
        # Check if user needs to change password
        user = form.get_user()
        if user.force_password_change:
            messages.warning(
                self.request,
                'You must change your password before continuing.'
            )
            return redirect('accounts:change_password')
        
        # Check password age
        if user.check_password_age():
            messages.info(
                self.request,
                'Your password is over 90 days old. Please consider changing it.'
            )
        
        # Set session expiry based on remember me
        if not form.cleaned_data.get('remember_me'):
            self.request.session.set_expiry(0)  # Browser close
        else:
            self.request.session.set_expiry(86400 * 7)  # 7 days
        
        return super().form_valid(form)


@login_required
@never_cache
def logout_view(request):
    """
    Secure logout with session clearing.
    """
    if request.user.is_authenticated:
        # Log logout
        SecurityAuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
        )
    
    # Clear session
    logout(request)
    request.session.flush()
    
    messages.success(request, 'You have been logged out successfully.')
    return redirect('home')


class PasswordResetView(FormView):
    """
    Password reset request with rate limiting.
    """
    template_name = 'accounts/password_reset.html'
    form_class = SecurePasswordResetForm
    success_url = reverse_lazy('accounts:password_reset_done')
    
    @method_decorator(ratelimit(key='ip', rate='5/h', method='POST'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def form_valid(self, form):
        """Send password reset email."""
        form.save(request=self.request)
        return super().form_valid(form)


class PasswordResetConfirmView(FormView):
    """
    Password reset confirmation with token validation.
    """
    template_name = 'accounts/password_reset_confirm.html'
    form_class = SecureSetPasswordForm
    success_url = reverse_lazy('accounts:password_reset_complete')
    
    @method_decorator(sensitive_post_parameters('new_password1', 'new_password2'))
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def get(self, request, token):
        """Validate token and show form."""
        try:
            reset_token = PasswordResetToken.objects.get(
                token=token,
                is_used=False
            )
            
            if reset_token.is_expired():
                messages.error(request, 'This reset link has expired.')
                return redirect('accounts:password_reset')
            
            self.user = reset_token.user
            return super().get(request)
            
        except PasswordResetToken.DoesNotExist:
            raise Http404("Invalid reset link")
    
    def post(self, request, token):
        """Handle password reset."""
        try:
            reset_token = PasswordResetToken.objects.get(
                token=token,
                is_used=False
            )
            
            if reset_token.is_expired():
                messages.error(request, 'This reset link has expired.')
                return redirect('accounts:password_reset')
            
            self.user = reset_token.user
            return super().post(request)
            
        except PasswordResetToken.DoesNotExist:
            raise Http404("Invalid reset link")
    
    def get_form_kwargs(self):
        """Add user to form kwargs."""
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs
    
    def form_valid(self, form):
        """Save new password and invalidate token."""
        form.save()
        
        # Invalidate token
        token = self.kwargs.get('token')
        PasswordResetToken.objects.filter(token=token).update(
            is_used=True,
            used_at=timezone.now()
        )
        
        messages.success(
            self.request,
            'Password reset successful! You can now log in with your new password.'
        )
        
        return super().form_valid(form)


@login_required
@csrf_protect
@sensitive_post_parameters('old_password', 'new_password1', 'new_password2')
@ratelimit(key='user', rate='5/h', method='POST')
def change_password_view(request):
    """
    Change password for authenticated users.
    """
    if request.method == 'POST':
        form = SecurePasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keep user logged in
            
            messages.success(request, 'Your password was successfully updated!')
            return redirect('dashboard')
    else:
        form = SecurePasswordChangeForm(request.user)
    
    return render(request, 'accounts/change_password.html', {
        'form': form
    })


class TwoFactorSetupView(LoginRequiredMixin, TwoFactorSetupView):
    """
    Two-factor authentication setup.
    """
    template_name = 'accounts/two_factor_setup.html'
    success_url = reverse_lazy('accounts:two_factor_backup')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Enable Two-Factor Authentication'
        return context
    
    def done(self, **kwargs):
        """Mark 2FA as enabled and log."""
        response = super().done(**kwargs)
        
        # Update user
        self.request.user.two_factor_enabled = True
        self.request.user.save(update_fields=['two_factor_enabled'])
        
        # Log 2FA enablement
        SecurityAuditLog.objects.create(
            user=self.request.user,
            action='2FA_ENABLED',
            ip_address=get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')[:255]
        )
        
        messages.success(
            self.request,
            'Two-factor authentication has been enabled successfully!'
        )
        
        return response


@login_required
@never_cache
def two_factor_backup_codes(request):
    """
    Display backup codes after 2FA setup.
    """
    if not request.user.two_factor_enabled:
        return redirect('accounts:two_factor_setup')
    
    # Generate backup codes if not already generated
    from django_otp.plugins.otp_static.models import StaticToken
    
    tokens = StaticToken.objects.filter(
        device__user=request.user,
        device__name='backup'
    )
    
    if not tokens.exists():
        # Generate 10 backup codes
        from django_otp.plugins.otp_static.models import StaticDevice
        device = StaticDevice.objects.create(
            user=request.user,
            name='backup'
        )
        
        tokens = []
        for _ in range(10):
            token = StaticToken.random_token()
            tokens.append(
                StaticToken.objects.create(
                    device=device,
                    token=token
                )
            )
        
        request.user.backup_codes_generated = timezone.now()
        request.user.save(update_fields=['backup_codes_generated'])
    
    return render(request, 'accounts/two_factor_backup.html', {
        'tokens': tokens,
        'title': 'Two-Factor Backup Codes'
    })


@login_required
def two_factor_qr_code(request):
    """
    Generate QR code for 2FA setup.
    """
    from django_otp.plugins.otp_totp.models import TOTPDevice
    
    # Get or create TOTP device
    device = TOTPDevice.objects.filter(
        user=request.user,
        confirmed=False
    ).first()
    
    if not device:
        device = TOTPDevice.objects.create(
            user=request.user,
            name='default'
        )
    
    # Generate QR code
    url = device.config_url
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return JsonResponse({
        'qr_code': f'data:image/png;base64,{img_str}',
        'secret': device.key
    })


# Error Handlers
def bad_request(request, exception=None):
    """400 error handler."""
    return render(request, 'errors/400.html', status=400)


def permission_denied(request, exception=None):
    """403 error handler."""
    return render(request, 'errors/403.html', status=403)


def not_found(request, exception=None):
    """404 error handler."""
    return render(request, 'errors/404.html', status=404)


def server_error(request):
    """500 error handler."""
    return render(request, 'errors/500.html', status=500)


def csrf_failure(request, reason=""):
    """CSRF failure handler."""
    return render(request, 'errors/csrf_failure.html', {
        'reason': reason
    }, status=403)


def ratelimit_exceeded(request, exception=None):
    """Rate limit exceeded handler."""
    return render(request, 'errors/ratelimit.html', status=429)
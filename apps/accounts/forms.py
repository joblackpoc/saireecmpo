"""
Forms for user registration, login, and password management.
Includes security features like CAPTCHA and strong password validation.
"""

from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordChangeForm as BasePasswordChangeForm,
    PasswordResetForm as BasePasswordResetForm, SetPasswordForm as BaseSetPasswordForm
)
from django.contrib.auth import authenticate, password_validation
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
import re
import requests
from honeypot.decorators import check_honeypot

from .models import EmailUser, SecurityAuditLog, PasswordResetToken


class TurnstileWidget(forms.widgets.Widget):
    """Custom widget for Cloudflare Turnstile CAPTCHA."""
    
    def render(self, name, value, attrs=None, renderer=None):
        return f'''
        <div class="cf-turnstile" 
             data-sitekey="{settings.TURNSTILE_SITE_KEY}"
             data-theme="light"
             data-size="normal">
        </div>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        '''


class TurnstileField(forms.CharField):
    """Custom field for Cloudflare Turnstile validation."""
    
    widget = TurnstileWidget
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.required = True
        
    def validate(self, value):
        super().validate(value)
        # Skip validation in development if no key configured
        if not settings.TURNSTILE_SECRET_KEY:
            return
            
        # Verify with Cloudflare
        response = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': settings.TURNSTILE_SECRET_KEY,
                'response': value,
            }
        )
        result = response.json()
        
        if not result.get('success'):
            raise ValidationError(_('CAPTCHA verification failed. Please try again.'))


class StrongPasswordMixin:
    """Mixin for forms requiring strong password validation."""
    
    def clean_password1(self):
        """Enhanced password validation."""
        password = self.cleaned_data.get('password1')
        
        if not password:
            return password
            
        # Check minimum length (12 characters)
        if len(password) < 12:
            raise ValidationError(
                _('Password must be at least 12 characters long.')
            )
        
        # Check for common patterns
        common_patterns = [
            r'^[0-9]+$',  # All numbers
            r'^[a-zA-Z]+$',  # All letters
            r'^(.)\1+$',  # Same character repeated
            r'(password|admin|user|root|test)',  # Common words
            r'(123|abc|qwerty)',  # Common sequences
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                raise ValidationError(
                    _('Password is too common or follows a predictable pattern.')
                )
        
        # Check complexity (must have at least 3 of: uppercase, lowercase, digits, special)
        complexity_score = 0
        if re.search(r'[a-z]', password):
            complexity_score += 1
        if re.search(r'[A-Z]', password):
            complexity_score += 1
        if re.search(r'[0-9]', password):
            complexity_score += 1
        if re.search(r'[^a-zA-Z0-9]', password):
            complexity_score += 1
            
        if complexity_score < 3:
            raise ValidationError(
                _('Password must contain at least 3 of: uppercase letters, '
                  'lowercase letters, digits, special characters.')
            )
        
        # Use Django's built-in validators
        password_validation.validate_password(password)
        
        return password


class UserRegistrationForm(forms.ModelForm, StrongPasswordMixin):
    """
    Secure user registration form with email verification.
    Includes CAPTCHA and honeypot for bot protection.
    """
    
    email = forms.EmailField(
        label=_('Email Address'),
        max_length=255,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'your.email@example.com',
            'autocomplete': 'email',
            'required': True,
        })
    )
    
    password1 = forms.CharField(
        label=_('Password'),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter a strong password',
            'autocomplete': 'new-password',
            'required': True,
        }),
        help_text=password_validation.password_validators_help_text_html(),
    )
    
    password2 = forms.CharField(
        label=_('Confirm Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm your password',
            'autocomplete': 'new-password',
            'required': True,
        }),
        strip=False,
    )
    
    first_name = forms.CharField(
        label=_('First Name'),
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'John',
            'autocomplete': 'given-name',
        })
    )
    
    last_name = forms.CharField(
        label=_('Last Name'),
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Doe',
            'autocomplete': 'family-name',
        })
    )
    
    # Honeypot field for bot detection (hidden via CSS)
    username = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label='Leave empty'
    )
    
    # CAPTCHA field
    captcha = TurnstileField(
        label='',
        required=True
    )
    
    # Terms acceptance
    accept_terms = forms.BooleanField(
        label=_('I accept the Terms of Service and Privacy Policy'),
        required=True,
        widget=forms.CheckboxInput(attrs={'required': True})
    )
    
    # Privacy consent (GDPR)
    data_privacy_consent = forms.BooleanField(
        label=_('I consent to the processing of my personal data'),
        required=True,
        widget=forms.CheckboxInput(attrs={'required': True})
    )
    
    class Meta:
        model = EmailUser
        fields = ('email', 'first_name', 'last_name')
    
    def clean_username(self):
        """Honeypot validation - should be empty."""
        username = self.cleaned_data.get('username')
        if username:
            # Log potential bot attempt
            SecurityAuditLog.objects.create(
                action='SUSPICIOUS_ACTIVITY',
                details={'type': 'honeypot_triggered', 'form': 'registration'}
            )
            raise ValidationError(_('Invalid form submission.'))
        return username
    
    def clean_email(self):
        """Validate email uniqueness and format."""
        email = self.cleaned_data.get('email')
        
        if not email:
            return email
            
        # Normalize email
        email = email.lower().strip()
        
        # Check for disposable email domains
        disposable_domains = [
            'tempmail.com', 'throwaway.email', '10minutemail.com',
            'guerrillamail.com', 'mailinator.com'
        ]
        domain = email.split('@')[-1]
        if domain in disposable_domains:
            raise ValidationError(
                _('Please use a permanent email address.')
            )
        
        # Check if email already exists
        if EmailUser.objects.filter(email__iexact=email).exists():
            raise ValidationError(
                _('An account with this email already exists.')
            )
        
        return email
    
    def clean_password2(self):
        """Validate password confirmation."""
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                _('Passwords do not match.')
            )
        
        return password2
    
    def save(self, commit=True, request=None):
        """Save user with security defaults."""
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.password_changed_at = timezone.now()
        user.data_privacy_consent = self.cleaned_data.get('data_privacy_consent', False)
        user.consent_timestamp = timezone.now() if user.data_privacy_consent else None
        
        # Capture registration metadata
        if request:
            user.registration_ip = self.get_client_ip(request)
            user.registration_user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
        
        if commit:
            user.save()
            
            # Log registration
            SecurityAuditLog.objects.create(
                user=user,
                action='USER_CREATED',
                ip_address=user.registration_ip,
                user_agent=user.registration_user_agent,
                details={'source': 'registration_form'}
            )
        
        return user
    
    def get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecureLoginForm(AuthenticationForm):
    """
    Enhanced login form with security features.
    Includes CAPTCHA after failed attempts and audit logging.
    """
    
    username = forms.EmailField(
        label=_('Email'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'your.email@example.com',
            'autocomplete': 'email',
            'autofocus': True,
            'required': True,
        })
    )
    
    password = forms.CharField(
        label=_('Password'),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password',
            'required': True,
        })
    )
    
    remember_me = forms.BooleanField(
        label=_('Remember me'),
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    # CAPTCHA field (conditionally required)
    captcha = TurnstileField(
        label='',
        required=False  # Will be required after failed attempts
    )
    
    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        super().__init__(request, *args, **kwargs)
        
        # Check if CAPTCHA should be required
        if request and request.session.get('failed_login_attempts', 0) >= 3:
            self.fields['captcha'].required = True
    
    def clean(self):
        """Authenticate with additional security checks."""
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        
        if username is not None and password:
            # Normalize email
            username = username.lower().strip()
            
            # Check if user exists and is not locked
            try:
                user = EmailUser.objects.get(email__iexact=username)
                
                # Check if account is locked
                if user.is_account_locked():
                    raise ValidationError(
                        _('This account has been locked due to multiple failed login attempts. '
                          'Please try again later or contact support.'),
                        code='account_locked'
                    )
                
                # Check if email is verified
                if not user.email_verified:
                    raise ValidationError(
                        _('Please verify your email address before logging in.'),
                        code='email_not_verified'
                    )
                
            except EmailUser.DoesNotExist:
                pass  # Let authenticate handle invalid credentials
            
            # Authenticate
            self.user_cache = authenticate(
                self.request,
                username=username,
                password=password
            )
            
            if self.user_cache is None:
                # Log failed attempt
                if self.request:
                    ip = self.get_client_ip(self.request)
                    user_agent = self.request.META.get('HTTP_USER_AGENT', '')[:255]
                    
                    # Try to get user for logging
                    try:
                        user = EmailUser.objects.get(email__iexact=username)
                        user.record_failed_login()
                        SecurityAuditLog.objects.create(
                            user=user,
                            action='LOGIN_FAILED',
                            ip_address=ip,
                            user_agent=user_agent
                        )
                    except EmailUser.DoesNotExist:
                        # Log failed attempt without user
                        SecurityAuditLog.objects.create(
                            action='LOGIN_FAILED',
                            ip_address=ip,
                            user_agent=user_agent,
                            details={'email': username}
                        )
                    
                    # Track failed attempts in session
                    self.request.session['failed_login_attempts'] = \
                        self.request.session.get('failed_login_attempts', 0) + 1
                
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user_cache)
                
                # Log successful login
                if self.request:
                    ip = self.get_client_ip(self.request)
                    user_agent = self.request.META.get('HTTP_USER_AGENT', '')[:255]
                    self.user_cache.record_login(ip, user_agent)
                    SecurityAuditLog.objects.create(
                        user=self.user_cache,
                        action='LOGIN_SUCCESS',
                        ip_address=ip,
                        user_agent=user_agent
                    )
                    
                    # Reset failed attempts
                    self.request.session['failed_login_attempts'] = 0
        
        return self.cleaned_data
    
    def get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurePasswordResetForm(BasePasswordResetForm):
    """
    Password reset form with rate limiting and security logging.
    """
    
    email = forms.EmailField(
        label=_('Email'),
        max_length=255,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'your.email@example.com',
            'autocomplete': 'email',
            'required': True,
        })
    )
    
    captcha = TurnstileField(
        label='',
        required=True
    )
    
    def clean_email(self):
        """Validate email and check for abuse."""
        email = self.cleaned_data.get('email')
        
        if not email:
            return email
        
        # Normalize email
        email = email.lower().strip()
        
        # Check if too many reset attempts
        recent_tokens = PasswordResetToken.objects.filter(
            user__email__iexact=email,
            created_at__gte=timezone.now() - timezone.timedelta(hours=1)
        ).count()
        
        if recent_tokens >= 3:
            raise ValidationError(
                _('Too many password reset attempts. Please try again later.')
            )
        
        return email
    
    def save(self, request=None, **kwargs):
        """Send password reset email with security token."""
        email = self.cleaned_data['email']
        
        try:
            user = EmailUser.objects.get(email__iexact=email, is_active=True)
            
            # Create reset token
            token = PasswordResetToken.objects.create(
                user=user,
                ip_address=self.get_client_ip(request) if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255] if request else ''
            )
            
            # Log password reset request
            SecurityAuditLog.objects.create(
                user=user,
                action='PASSWORD_RESET',
                ip_address=token.ip_address,
                user_agent=token.user_agent,
                details={'token_id': str(token.id)}
            )
            
            # Send email (implement email sending logic)
            # super().save(**kwargs)
            
        except EmailUser.DoesNotExist:
            # Don't reveal if email exists
            pass
        
        return email
    
    def get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecureSetPasswordForm(BaseSetPasswordForm, StrongPasswordMixin):
    """
    Password reset confirmation form with strong password requirements.
    """
    
    new_password1 = forms.CharField(
        label=_('New password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password',
            'required': True,
        }),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    
    new_password2 = forms.CharField(
        label=_('Confirm new password'),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password',
            'required': True,
        })
    )
    
    def save(self, commit=True):
        """Save new password with security updates."""
        user = super().save(commit=False)
        user.password_changed_at = timezone.now()
        user.force_password_change = False
        user.failed_login_attempts = 0
        
        if commit:
            user.save()
            
            # Log password change
            SecurityAuditLog.objects.create(
                user=user,
                action='PASSWORD_CHANGED',
                details={'source': 'password_reset'}
            )
        
        return user


class SecurePasswordChangeForm(BasePasswordChangeForm, StrongPasswordMixin):
    """
    Password change form for authenticated users.
    """
    
    old_password = forms.CharField(
        label=_('Current password'),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter current password',
            'autocomplete': 'current-password',
            'autofocus': True,
            'required': True,
        })
    )
    
    new_password1 = forms.CharField(
        label=_('New password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password',
            'required': True,
        }),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    
    new_password2 = forms.CharField(
        label=_('Confirm new password'),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password',
            'required': True,
        })
    )
    
    def clean_new_password1(self):
        """Ensure new password is different from old."""
        old_password = self.cleaned_data.get('old_password')
        new_password = self.cleaned_data.get('new_password1')
        
        if old_password and new_password and old_password == new_password:
            raise ValidationError(
                _('New password must be different from current password.')
            )
        
        # Apply strong password validation
        return super().clean_password1()
    
    def save(self, commit=True):
        """Save password change with security logging."""
        user = super().save(commit=False)
        user.password_changed_at = timezone.now()
        user.force_password_change = False
        
        if commit:
            user.save()
            
            # Log password change
            SecurityAuditLog.objects.create(
                user=user,
                action='PASSWORD_CHANGED',
                details={'source': 'password_change_form'}
            )
        
        return user
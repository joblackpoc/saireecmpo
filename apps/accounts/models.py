"""
Custom user model using email as username with enhanced security features.
Implements AbstractBaseUser and PermissionsMixin for full control.
"""

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, EmailValidator
from django.core.exceptions import ValidationError
import hashlib
import secrets
from datetime import timedelta
import uuid


class EmailUserManager(BaseUserManager):
    """
    Custom user manager for EmailUser model.
    Implements secure user creation with email normalization.
    """
    
    def normalize_email(self, email):
        """Override to ensure consistent email normalization"""
        email = email or ''
        try:
            email_name, domain_part = email.strip().rsplit('@', 1)
        except ValueError:
            pass
        else:
            email = email_name.lower() + '@' + domain_part.lower()
        return email
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a regular user with the given email and password.
        Security: Auto-disable users until email verification.
        """
        if not email:
            raise ValueError(_('Email address is required'))
        
        # Normalize and validate email
        email = self.normalize_email(email)
        EmailValidator()(email)  # Additional validation
        
        # Security defaults
        extra_fields.setdefault('is_active', False)  # Require email verification
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        
        user = self.model(email=email, **extra_fields)
        
        # Use set_password for proper hashing
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        
        user.save(using=self._db)
        
        # Create email verification token
        EmailVerificationToken.objects.create(user=user)
        
        # Log user creation for security audit
        SecurityAuditLog.objects.create(
            user=user,
            action='USER_CREATED',
            ip_address=extra_fields.get('registration_ip', ''),
            user_agent=extra_fields.get('registration_user_agent', '')
        )
        
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a superuser with the given email and password.
        Security: Enforce strong password for superusers.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)  # Superusers are pre-verified
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        # Enforce minimum password length for superusers
        if password and len(password) < 16:
            raise ValidationError(_('Superuser password must be at least 16 characters.'))
        
        return self.create_user(email, password, **extra_fields)


class EmailUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model using email instead of username.
    Includes security enhancements and audit fields.
    """
    
    # Unique identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Email as username
    email = models.EmailField(
        _('email address'),
        unique=True,
        max_length=255,
        validators=[EmailValidator()],
        error_messages={
            'unique': _('A user with this email already exists.'),
        },
    )
    
    # Profile fields
    first_name = models.CharField(_('first name'), max_length=50, blank=True)
    last_name = models.CharField(_('last name'), max_length=50, blank=True)
    display_name = models.CharField(
        _('display name'), 
        max_length=100, 
        blank=True,
        help_text=_('Public display name (optional)')
    )
    
    # Security fields
    is_active = models.BooleanField(
        _('active'),
        default=False,  # Require email verification
        help_text=_('Unselect this instead of deleting accounts.')
    )
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into admin site.')
    )
    email_verified = models.BooleanField(
        _('email verified'),
        default=False,
        help_text=_('Whether email address has been verified.')
    )
    
    # Two-factor authentication
    two_factor_enabled = models.BooleanField(
        _('2FA enabled'),
        default=False,
        help_text=_('Whether two-factor authentication is enabled.')
    )
    backup_codes_generated = models.DateTimeField(
        _('backup codes generated'),
        null=True,
        blank=True,
        help_text=_('When 2FA backup codes were last generated.')
    )
    
    # Account security
    password_changed_at = models.DateTimeField(
        _('password last changed'),
        null=True,
        blank=True
    )
    force_password_change = models.BooleanField(
        _('force password change'),
        default=False,
        help_text=_('User must change password on next login.')
    )
    
    # Login tracking
    last_login_ip = models.GenericIPAddressField(
        _('last login IP'),
        null=True,
        blank=True
    )
    last_login_user_agent = models.CharField(
        _('last login user agent'),
        max_length=255,
        blank=True
    )
    failed_login_attempts = models.PositiveIntegerField(
        _('failed login attempts'),
        default=0
    )
    last_failed_login = models.DateTimeField(
        _('last failed login'),
        null=True,
        blank=True
    )
    
    # Registration tracking
    registration_ip = models.GenericIPAddressField(
        _('registration IP'),
        null=True,
        blank=True
    )
    registration_user_agent = models.CharField(
        _('registration user agent'),
        max_length=255,
        blank=True
    )
    
    # Timestamps
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    updated_at = models.DateTimeField(_('last updated'), auto_now=True)
    
    # Account status
    is_locked = models.BooleanField(
        _('account locked'),
        default=False,
        help_text=_('Account locked due to security reasons.')
    )
    locked_until = models.DateTimeField(
        _('locked until'),
        null=True,
        blank=True,
        help_text=_('Account locked until this time.')
    )
    
    # Privacy settings
    data_privacy_consent = models.BooleanField(
        _('data privacy consent'),
        default=False,
        help_text=_('User has consented to data processing.')
    )
    consent_timestamp = models.DateTimeField(
        _('consent timestamp'),
        null=True,
        blank=True
    )
    
    objects = EmailUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email is already required as USERNAME_FIELD
    
    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        db_table = 'accounts_users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active', 'is_staff']),
            models.Index(fields=['date_joined']),
        ]
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        full_name = f'{self.first_name} {self.last_name}'.strip()
        return full_name or self.email
    
    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name or self.email.split('@')[0]
    
    def get_display_name(self):
        """Return display name or fall back to email prefix."""
        return self.display_name or self.get_short_name()
    
    def check_password_age(self):
        """Check if password needs to be changed (90 days policy)."""
        if not self.password_changed_at:
            return True
        age = timezone.now() - self.password_changed_at
        return age.days > 90
    
    def is_account_locked(self):
        """Check if account is currently locked."""
        if self.is_locked:
            if self.locked_until and self.locked_until > timezone.now():
                return True
            # Unlock if time has passed
            self.is_locked = False
            self.locked_until = None
            self.save(update_fields=['is_locked', 'locked_until'])
        return False
    
    def lock_account(self, duration_hours=1):
        """Lock account for specified duration."""
        self.is_locked = True
        self.locked_until = timezone.now() + timedelta(hours=duration_hours)
        self.save(update_fields=['is_locked', 'locked_until'])
    
    def record_login(self, ip_address=None, user_agent=None):
        """Record successful login details."""
        self.last_login = timezone.now()
        self.last_login_ip = ip_address
        self.last_login_user_agent = user_agent[:255] if user_agent else ''
        self.failed_login_attempts = 0
        self.save(update_fields=[
            'last_login', 'last_login_ip', 
            'last_login_user_agent', 'failed_login_attempts'
        ])
    
    def record_failed_login(self):
        """Record failed login attempt."""
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        self.save(update_fields=['failed_login_attempts', 'last_failed_login'])
        
        # Auto-lock after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.lock_account(duration_hours=1)


class EmailVerificationToken(models.Model):
    """
    Email verification tokens with expiration.
    Uses secure random tokens instead of predictable hashes.
    """
    
    user = models.ForeignKey(
        EmailUser,
        on_delete=models.CASCADE,
        related_name='email_tokens'
    )
    token = models.CharField(
        max_length=64,
        unique=True,
        default=lambda: secrets.token_urlsafe(48)
    )
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'accounts_email_tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_used']),
        ]
    
    def is_expired(self):
        """Check if token has expired (24 hours)."""
        age = timezone.now() - self.created_at
        return age.total_seconds() > 86400  # 24 hours
    
    def use(self):
        """Mark token as used."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])
        
        # Activate user account
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save(update_fields=['email_verified', 'is_active'])


class PasswordResetToken(models.Model):
    """
    Secure password reset tokens with expiration and single use.
    """
    
    user = models.ForeignKey(
        EmailUser,
        on_delete=models.CASCADE,
        related_name='password_tokens'
    )
    token = models.CharField(
        max_length=64,
        unique=True,
        default=lambda: secrets.token_urlsafe(48)
    )
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    
    class Meta:
        db_table = 'accounts_password_tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_used']),
        ]
    
    def is_expired(self):
        """Check if token has expired (1 hour for security)."""
        age = timezone.now() - self.created_at
        return age.total_seconds() > 3600  # 1 hour
    
    def use(self):
        """Mark token as used."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])


class SecurityAuditLog(models.Model):
    """
    Security audit log for tracking important account events.
    Required for compliance and security monitoring.
    """
    
    ACTION_CHOICES = [
        ('USER_CREATED', 'User Created'),
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('PASSWORD_CHANGED', 'Password Changed'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('EMAIL_VERIFIED', 'Email Verified'),
        ('2FA_ENABLED', '2FA Enabled'),
        ('2FA_DISABLED', '2FA Disabled'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('ACCOUNT_UNLOCKED', 'Account Unlocked'),
        ('PERMISSION_CHANGED', 'Permission Changed'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
    ]
    
    user = models.ForeignKey(
        EmailUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'accounts_audit_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'action']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address']),
        ]
    
    def __str__(self):
        return f'{self.user} - {self.action} - {self.timestamp}'
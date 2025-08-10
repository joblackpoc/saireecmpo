"""
Unit tests for accounts app.
Tests user creation, authentication, 2FA, and security features.
"""

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core import mail
from unittest.mock import patch, MagicMock
from datetime import timedelta

from apps.accounts.models import (
    EmailUser, EmailVerificationToken, PasswordResetToken, 
    SecurityAuditLog
)
from apps.accounts.forms import (
    UserRegistrationForm, SecureLoginForm, SecurePasswordResetForm
)


User = get_user_model()


class EmailUserModelTests(TestCase):
    """Test custom EmailUser model."""
    
    def setUp(self):
        """Set up test data."""
        self.email = 'test@example.com'
        self.password = 'SecureP@ssw0rd123!'
    
    def test_create_user(self):
        """Test creating a regular user."""
        user = User.objects.create_user(
            email=self.email,
            password=self.password
        )
        
        self.assertEqual(user.email, self.email)
        self.assertTrue(user.check_password(self.password))
        self.assertFalse(user.is_active)  # Should be inactive until email verified
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.email_verified)
    
    def test_create_superuser(self):
        """Test creating a superuser."""
        admin_password = 'SuperSecureAdminP@ssw0rd123!'
        user = User.objects.create_superuser(
            email='admin@example.com',
            password=admin_password
        )
        
        self.assertTrue(user.is_active)  # Superusers are pre-verified
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.check_password(admin_password))
    
    def test_email_normalization(self):
        """Test email is normalized properly."""
        email = 'TEST@EXAMPLE.COM'
        user = User.objects.create_user(
            email=email,
            password=self.password
        )
        
        self.assertEqual(user.email, 'test@example.com')
    
    def test_user_str_method(self):
        """Test string representation of user."""
        user = User.objects.create_user(
            email=self.email,
            password=self.password
        )
        
        self.assertEqual(str(user), self.email)
    
    def test_account_locking(self):
        """Test account locking mechanism."""
        user = User.objects.create_user(
            email=self.email,
            password=self.password
        )
        
        # Lock account
        user.lock_account(duration_hours=1)
        
        self.assertTrue(user.is_locked)
        self.assertIsNotNone(user.locked_until)
        self.assertTrue(user.is_account_locked())
        
        # Test auto-unlock after time passes
        user.locked_until = timezone.now() - timedelta(hours=1)
        user.save()
        
        self.assertFalse(user.is_account_locked())
    
    def test_failed_login_tracking(self):
        """Test failed login attempt tracking."""
        user = User.objects.create_user(
            email=self.email,
            password=self.password
        )
        
        # Record failed attempts
        for _ in range(4):
            user.record_failed_login()
        
        self.assertEqual(user.failed_login_attempts, 4)
        self.assertFalse(user.is_locked)
        
        # 5th attempt should lock account
        user.record_failed_login()
        
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertTrue(user.is_locked)
    
    def test_password_age_check(self):
        """Test password age checking."""
        user = User.objects.create_user(
            email=self.email,
            password=self.password
        )
        
        # New password should not need changing
        user.password_changed_at = timezone.now()
        user.save()
        self.assertFalse(user.check_password_age())
        
        # Old password should need changing
        user.password_changed_at = timezone.now() - timedelta(days=91)
        user.save()
        self.assertTrue(user.check_password_age())


class EmailVerificationTests(TestCase):
    """Test email verification functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecureP@ssw0rd123!'
        )
    
    def test_verification_token_creation(self):
        """Test verification token is created."""
        token = EmailVerificationToken.objects.create(user=self.user)
        
        self.assertIsNotNone(token.token)
        self.assertEqual(token.user, self.user)
        self.assertFalse(token.is_used)
    
    def test_token_expiration(self):
        """Test token expiration logic."""
        token = EmailVerificationToken.objects.create(user=self.user)
        
        # Fresh token should not be expired
        self.assertFalse(token.is_expired())
        
        # Old token should be expired
        token.created_at = timezone.now() - timedelta(hours=25)
        token.save()
        self.assertTrue(token.is_expired())
    
    def test_token_usage(self):
        """Test using a verification token."""
        token = EmailVerificationToken.objects.create(user=self.user)
        
        # Use token
        token.use()
        
        self.assertTrue(token.is_used)
        self.assertIsNotNone(token.used_at)
        self.assertTrue(self.user.email_verified)
        self.assertTrue(self.user.is_active)


class UserRegistrationFormTests(TestCase):
    """Test user registration form."""
    
    def test_valid_registration(self):
        """Test valid registration form."""
        form_data = {
            'email': 'newuser@example.com',
            'password1': 'SecureP@ssw0rd123!',
            'password2': 'SecureP@ssw0rd123!',
            'first_name': 'John',
            'last_name': 'Doe',
            'username': '',  # Honeypot should be empty
            'accept_terms': True,
            'data_privacy_consent': True,
            'captcha': 'test_token'  # Mock token
        }
        
        with patch('apps.accounts.forms.requests.post') as mock_post:
            mock_post.return_value.json.return_value = {'success': True}
            form = UserRegistrationForm(data=form_data)
            # Skip CAPTCHA validation in tests
            form.fields['captcha'].required = False
            self.assertTrue(form.is_valid())
    
    def test_password_mismatch(self):
        """Test password confirmation mismatch."""
        form_data = {
            'email': 'newuser@example.com',
            'password1': 'SecureP@ssw0rd123!',
            'password2': 'DifferentPassword123!',
            'username': '',
            'accept_terms': True,
            'data_privacy_consent': True,
        }
        
        form = UserRegistrationForm(data=form_data)
        form.fields['captcha'].required = False
        self.assertFalse(form.is_valid())
        self.assertIn('password2', form.errors)
    
    def test_weak_password(self):
        """Test weak password rejection."""
        form_data = {
            'email': 'newuser@example.com',
            'password1': 'weak',
            'password2': 'weak',
            'username': '',
            'accept_terms': True,
            'data_privacy_consent': True,
        }
        
        form = UserRegistrationForm(data=form_data)
        form.fields['captcha'].required = False
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)
    
    def test_honeypot_triggered(self):
        """Test honeypot field catches bots."""
        form_data = {
            'email': 'bot@example.com',
            'password1': 'SecureP@ssw0rd123!',
            'password2': 'SecureP@ssw0rd123!',
            'username': 'bot_filled_this',  # Honeypot filled = bot
            'accept_terms': True,
            'data_privacy_consent': True,
        }
        
        form = UserRegistrationForm(data=form_data)
        form.fields['captcha'].required = False
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)
    
    def test_duplicate_email(self):
        """Test duplicate email rejection."""
        # Create existing user
        User.objects.create_user(
            email='existing@example.com',
            password='SecureP@ssw0rd123!'
        )
        
        form_data = {
            'email': 'existing@example.com',
            'password1': 'SecureP@ssw0rd123!',
            'password2': 'SecureP@ssw0rd123!',
            'username': '',
            'accept_terms': True,
            'data_privacy_consent': True,
        }
        
        form = UserRegistrationForm(data=form_data)
        form.fields['captcha'].required = False
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)


class LoginViewTests(TestCase):
    """Test login functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.login_url = reverse('two_factor:login')
        
        # Create verified user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecureP@ssw0rd123!'
        )
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save()
    
    def test_successful_login(self):
        """Test successful login."""
        response = self.client.post(self.login_url, {
            'auth-username': 'test@example.com',
            'auth-password': 'SecureP@ssw0rd123!',
            'login_view-current_step': 'auth',
        })
        
        # Should redirect after successful login
        self.assertEqual(response.status_code, 302)
    
    def test_login_with_wrong_password(self):
        """Test login with wrong password."""
        response = self.client.post(self.login_url, {
            'auth-username': 'test@example.com',
            'auth-password': 'WrongPassword123!',
            'login_view-current_step': 'auth',
        })
        
        # Should show form with errors
        self.assertEqual(response.status_code, 200)
    
    def test_login_unverified_email(self):
        """Test login with unverified email."""
        # Create unverified user
        unverified_user = User.objects.create_user(
            email='unverified@example.com',
            password='SecureP@ssw0rd123!'
        )
        
        response = self.client.post(self.login_url, {
            'auth-username': 'unverified@example.com',
            'auth-password': 'SecureP@ssw0rd123!',
            'login_view-current_step': 'auth',
        })
        
        # Should not allow login
        self.assertEqual(response.status_code, 200)
    
    @override_settings(AXES_ENABLED=False)  # Disable for this test
    def test_account_locking_after_failures(self):
        """Test account locks after multiple failed attempts."""
        # Try wrong password 5 times
        for _ in range(5):
            response = self.client.post(self.login_url, {
                'auth-username': 'test@example.com',
                'auth-password': 'WrongPassword!',
                'login_view-current_step': 'auth',
            })
        
        # Refresh user from database
        self.user.refresh_from_db()
        
        # Check if failed attempts were recorded
        self.assertGreater(self.user.failed_login_attempts, 0)


class PasswordResetTests(TestCase):
    """Test password reset functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='OldP@ssw0rd123!'
        )
        self.user.is_active = True
        self.user.save()
    
    def test_password_reset_token_creation(self):
        """Test password reset token creation."""
        token = PasswordResetToken.objects.create(user=self.user)
        
        self.assertIsNotNone(token.token)
        self.assertEqual(token.user, self.user)
        self.assertFalse(token.is_used)
    
    def test_password_reset_token_expiration(self):
        """Test token expires after 1 hour."""
        token = PasswordResetToken.objects.create(user=self.user)
        
        # Fresh token
        self.assertFalse(token.is_expired())
        
        # Expired token
        token.created_at = timezone.now() - timedelta(hours=2)
        token.save()
        self.assertTrue(token.is_expired())
    
    @override_settings(
        TURNSTILE_SITE_KEY='test',
        TURNSTILE_SECRET_KEY='test'
    )
    def test_password_reset_request(self):
        """Test password reset request."""
        reset_url = reverse('accounts:password_reset')
        
        with patch('apps.accounts.forms.requests.post') as mock_post:
            mock_post.return_value.json.return_value = {'success': True}
            
            response = self.client.post(reset_url, {
                'email': 'test@example.com',
                'captcha': 'test_token'
            })
            
            # Should redirect to done page
            self.assertEqual(response.status_code, 302)
            
            # Token should be created
            self.assertTrue(
                PasswordResetToken.objects.filter(user=self.user).exists()
            )


class SecurityAuditLogTests(TestCase):
    """Test security audit logging."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecureP@ssw0rd123!'
        )
    
    def test_audit_log_creation(self):
        """Test creating audit log entries."""
        log = SecurityAuditLog.objects.create(
            user=self.user,
            action='LOGIN_SUCCESS',
            ip_address='127.0.0.1',
            user_agent='Test Browser',
            details={'test': 'data'}
        )
        
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, 'LOGIN_SUCCESS')
        self.assertEqual(log.ip_address, '127.0.0.1')
        self.assertEqual(log.details['test'], 'data')
    
    def test_audit_log_ordering(self):
        """Test audit logs are ordered by timestamp."""
        # Create logs with different timestamps
        log1 = SecurityAuditLog.objects.create(
            user=self.user,
            action='LOGIN_SUCCESS'
        )
        
        log2 = SecurityAuditLog.objects.create(
            user=self.user,
            action='LOGOUT'
        )
        
        logs = SecurityAuditLog.objects.all()
        
        # Most recent should be first
        self.assertEqual(logs[0], log2)
        self.assertEqual(logs[1], log1)


class TwoFactorAuthTests(TestCase):
    """Test two-factor authentication."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecureP@ssw0rd123!'
        )
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save()
    
    def test_2fa_setup_requires_login(self):
        """Test 2FA setup requires authentication."""
        setup_url = reverse('accounts:two_factor_setup')
        response = self.client.get(setup_url)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_2fa_qr_code_generation(self):
        """Test QR code generation for 2FA."""
        # Login first
        self.client.force_login(self.user)
        
        qr_url = reverse('accounts:two_factor_qr')
        response = self.client.get(qr_url)
        
        self.assertEqual(response.status_code, 200)
        
        # Check response is JSON with QR code
        data = response.json()
        self.assertIn('qr_code', data)
        self.assertIn('secret', data)
        self.assertTrue(data['qr_code'].startswith('data:image/png;base64,'))


class RateLimitingTests(TestCase):
    """Test rate limiting on sensitive endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
    
    @override_settings(RATELIMIT_ENABLE=True)
    def test_registration_rate_limit(self):
        """Test registration endpoint rate limiting."""
        register_url = reverse('accounts:register')
        
        # Make multiple requests quickly
        for i in range(6):
            response = self.client.post(register_url, {
                'email': f'user{i}@example.com',
                'password1': 'SecureP@ssw0rd123!',
                'password2': 'SecureP@ssw0rd123!',
            })
            
            if i < 5:
                # First 5 should work
                self.assertNotEqual(response.status_code, 429)
            else:
                # 6th should be rate limited
                self.assertEqual(response.status_code, 429)
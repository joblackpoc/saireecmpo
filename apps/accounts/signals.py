"""
Signal handlers for security events and user actions.
"""

from django.db.models.signals import post_save, pre_save, post_delete
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from .models import EmailUser, SecurityAuditLog


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """
    Log successful login and update user metadata.
    """
    # Get IP and user agent
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    
    # Update user login info
    user.last_login = timezone.now()
    user.last_login_ip = ip
    user.last_login_user_agent = user_agent
    user.failed_login_attempts = 0  # Reset on successful login
    user.save(update_fields=[
        'last_login', 'last_login_ip', 
        'last_login_user_agent', 'failed_login_attempts'
    ])
    
    # Create audit log
    SecurityAuditLog.objects.create(
        user=user,
        action='LOGIN_SUCCESS',
        ip_address=ip,
        user_agent=user_agent,
        details={'session_key': request.session.session_key}
    )
    
    # Clear any rate limit cache for this user
    cache_key = f'login_attempts_{user.email}'
    cache.delete(cache_key)


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """
    Log user logout.
    """
    if user:
        # Get IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Create audit log
        SecurityAuditLog.objects.create(
            user=user,
            action='LOGOUT',
            ip_address=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
        )


@receiver(user_login_failed)
def log_login_failed(sender, credentials, request, **kwargs):
    """
    Log failed login attempts for security monitoring.
    """
    # Get email from credentials
    email = credentials.get('username', '').lower()
    
    # Get IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    
    # Try to get user
    user = None
    if email:
        try:
            user = EmailUser.objects.get(email__iexact=email)
            # Update failed attempts
            user.failed_login_attempts += 1
            user.last_failed_login = timezone.now()
            user.save(update_fields=['failed_login_attempts', 'last_failed_login'])
            
            # Lock account after 5 attempts
            if user.failed_login_attempts >= 5:
                user.lock_account(duration_hours=1)
                
                # Log account lock
                SecurityAuditLog.objects.create(
                    user=user,
                    action='ACCOUNT_LOCKED',
                    ip_address=ip,
                    user_agent=user_agent,
                    details={'reason': 'too_many_failed_attempts'}
                )
        except EmailUser.DoesNotExist:
            pass
    
    # Create audit log
    SecurityAuditLog.objects.create(
        user=user,
        action='LOGIN_FAILED',
        ip_address=ip,
        user_agent=user_agent,
        details={'email': email}
    )
    
    # Track in cache for rate limiting
    cache_key = f'login_attempts_{email}'
    attempts = cache.get(cache_key, 0)
    cache.set(cache_key, attempts + 1, 3600)  # 1 hour expiry


@receiver(pre_save, sender=EmailUser)
def check_password_change(sender, instance, **kwargs):
    """
    Check if password was changed and update metadata.
    """
    if instance.pk:
        try:
            old_user = EmailUser.objects.get(pk=instance.pk)
            if instance.password != old_user.password:
                # Password was changed
                instance.password_changed_at = timezone.now()
                instance.force_password_change = False
                
                # Create audit log (will be saved after user is saved)
                # Using a flag to avoid creating log in pre_save
                instance._password_changed = True
        except EmailUser.DoesNotExist:
            pass


@receiver(post_save, sender=EmailUser)
def log_password_change(sender, instance, created, **kwargs):
    """
    Log password changes after save.
    """
    if not created and hasattr(instance, '_password_changed'):
        SecurityAuditLog.objects.create(
            user=instance,
            action='PASSWORD_CHANGED',
            details={'method': 'direct_update'}
        )
        delattr(instance, '_password_changed')


@receiver(post_delete, sender=EmailUser)
def log_user_deletion(sender, instance, **kwargs):
    """
    Log user account deletion for compliance.
    """
    # Store deletion record (in a separate model if needed for compliance)
    SecurityAuditLog.objects.create(
        user=None,  # User is deleted
        action='USER_DELETED',
        details={
            'email': instance.email,
            'user_id': str(instance.id),
            'deletion_date': timezone.now().isoformat()
        }
    )
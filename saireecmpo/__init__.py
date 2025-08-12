"""
SecureCMS - A security-hardened content management system built with Django 5.
Following OWASP Top 10 and NIST SP 800-53 security controls.
"""

__version__ = '1.0.0'
__author__ = 'SecureCMS Team'

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
try:
    from .celery import app as celery_app
    __all__ = ('celery_app',)
except ImportError:
    # Celery not configured yet
    pass

# Configure default Django settings module for 'celery' program.
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'saireecmpo.settings')
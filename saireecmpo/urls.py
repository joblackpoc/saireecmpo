"""
URL configuration for saireecmpo project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView
from two_factor.urls import urlpatterns as tf_urls
from two_factor.admin import AdminSiteOTPRequired
from django.contrib.auth import views as auth_views
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django_ratelimit.decorators import ratelimit

# Secure admin with OTP requirement
admin.site.__class__ = AdminSiteOTPRequired
admin.site.site_header = "SecureCMS Admin"
admin.site.site_title = "SecureCMS"
admin.site.index_title = "Welcome to SecureCMS Administration"

# Custom error handlers
handler400 = 'apps.accounts.views.bad_request'
handler403 = 'apps.accounts.views.permission_denied'
handler404 = 'apps.accounts.views.not_found'
handler500 = 'apps.accounts.views.server_error'

urlpatterns = [
    # Two-factor authentication URLs (must be before admin)
    path('', include(tf_urls)),
    
    # Admin with 2FA protection
    path('admin/', include('admin_honeypot.urls', namespace='admin')),
    path('secure-admin/', admin.site.urls),
    path('ckeditor5/', include('django_ckeditor_5.urls')),
    # Honeypot field for bot detection (fake login URL)
    path('accounts/login/', include('admin_honeypot.urls', namespace='login')),
    path('secure-login/', include('two_factor.urls', namespace='secure-login')),
    
    # Authentication URLs with rate limiting
    path('auth/', include('apps.accounts.urls', namespace='accounts')),
    
    # CMS URLs
    path('cms/', include('apps.cms.urls', namespace='cms')),
    
    # API endpoints with JWT authentication
    path('api/v1/', include('apps.api.urls', namespace='api')),
    
    # CKEditor 5 does not require a default uploader URL
    
    # Home page
    path('', TemplateView.as_view(template_name='home.html'), name='home'),
    
    # Dashboard (requires authentication)
    path('dashboard/', 
         never_cache(
             ratelimit(key='user', rate='100/h')(
                 TemplateView.as_view(template_name='dashboard.html')
             )
         ), 
         name='dashboard'),
    
    # Security.txt for responsible disclosure
    path('.well-known/security.txt', 
         TemplateView.as_view(
             template_name='security.txt',
             content_type='text/plain'
         ), 
         name='security-txt'),
    
    # Robots.txt
    path('robots.txt', 
         TemplateView.as_view(
             template_name='robots.txt',
             content_type='text/plain'
         ), 
         name='robots-txt'),
    
    # Health check endpoint for monitoring
    path('health/', 
         csrf_exempt(
             TemplateView.as_view(template_name='health.json', content_type='application/json')
         ), 
         name='health-check'),
]

# Serve media files in development only
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    try:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
    except ImportError:
        pass

# Add CSP report URL
urlpatterns += [
    path('csp-report/', 
         csrf_exempt(
             ratelimit(key='ip', rate='10/m')(
                 TemplateView.as_view(template_name='blank.html')
             )
         ), 
         name='csp-report'),
]
"""
URL configuration for API endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from . import views

app_name = 'api'

# Create router for viewsets
router = DefaultRouter()
router.register(r'pages', views.PageViewSet, basename='page')
router.register(r'categories', views.CategoryViewSet, basename='category')
router.register(r'tags', views.TagViewSet, basename='tag')

urlpatterns = [
    # API root
    path('', views.api_root, name='api-root'),
    
    # Health check
    path('health/', views.health_check, name='health-check'),
    
    # Authentication endpoints
    path('auth/login/', 
         views.CustomTokenObtainPairView.as_view(), 
         name='token_obtain_pair'),
    
    path('auth/refresh/', 
         TokenRefreshView.as_view(), 
         name='token_refresh'),
    
    path('auth/verify/', 
         TokenVerifyView.as_view(), 
         name='token_verify'),
    
    path('auth/register/', 
         views.UserRegistrationView.as_view(), 
         name='register'),
    
    # User endpoints
    path('profile/', 
         views.UserProfileView.as_view(), 
         name='profile'),
    
    # Page endpoints (special)
    path('pages/featured/', 
         views.FeaturedPagesView.as_view(), 
         name='featured-pages'),
    
    path('pages/my/', 
         views.MyPagesView.as_view(), 
         name='my-pages'),
    
    # Search
    path('search/', 
         views.SearchView.as_view(), 
         name='search'),
    
    # Statistics
    path('stats/', 
         views.StatsView.as_view(), 
         name='stats'),
    
    # Include router URLs
    path('', include(router.urls)),
]
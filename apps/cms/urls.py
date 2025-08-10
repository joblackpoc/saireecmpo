"""
URL configuration for CMS app.
"""

from django.urls import path
from django.views.decorators.cache import cache_page

from . import views

app_name = 'cms'

urlpatterns = [
    # Page URLs
    path('', 
         views.PageListView.as_view(), 
         name='page_list'),
    
    path('pages/create/', 
         views.PageCreateView.as_view(), 
         name='page_create'),
    
    path('pages/my/', 
         views.my_pages, 
         name='my_pages'),
    
    path('pages/featured/', 
         views.featured_pages, 
         name='featured_pages'),
    
    path('pages/bulk-action/', 
         views.bulk_action, 
         name='bulk_action'),
    
    # Page detail/edit/delete (using slug)
    path('page/<slug:slug>/', 
         views.PageDetailView.as_view(), 
         name='page_detail'),
    
    path('page/<slug:slug>/edit/', 
         views.PageUpdateView.as_view(), 
         name='page_edit'),
    
    path('page/<slug:slug>/delete/', 
         views.PageDeleteView.as_view(), 
         name='page_delete'),
    
    path('page/<slug:slug>/preview/', 
         views.page_preview, 
         name='page_preview'),
    
    path('page/<slug:slug>/publish/', 
         views.page_publish, 
         name='page_publish'),
    
    path('page/<slug:slug>/versions/', 
         views.page_version_history, 
         name='page_versions'),
    
    path('page/<slug:slug>/restore/<int:version_id>/', 
         views.page_restore_version, 
         name='page_restore'),
    
    # Category URLs
    path('categories/', 
         views.CategoryListView.as_view(), 
         name='category_list'),
    
    path('category/<slug:slug>/', 
         views.CategoryDetailView.as_view(), 
         name='category_detail'),
    
    # Tag URLs
    path('tag/<slug:slug>/', 
         views.TagDetailView.as_view(), 
         name='tag_detail'),
]
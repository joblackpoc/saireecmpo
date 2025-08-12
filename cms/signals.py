"""
Signal handlers for CMS events and page lifecycle.
"""

from django.db.models.signals import pre_save, post_save, pre_delete
from django.dispatch import receiver
from django.core.cache import cache
from django.utils import timezone

from .models import Page, PageVersion, PageAuditLog


@receiver(pre_save, sender=Page)
def sanitize_page_content(sender, instance, **kwargs):
    """
    Sanitize page content before saving.
    """
    # Content will be sanitized in the model's save method
    # This is a placeholder for additional pre-save logic
    
    # Clear cache for this page
    cache_key = f'page_{instance.slug}'
    cache.delete(cache_key)
    
    # Clear related caches
    if instance.category:
        cache.delete(f'category_{instance.category.slug}_pages')
    
    # Clear featured pages cache if needed
    if instance.featured:
        cache.delete('featured_pages')


@receiver(post_save, sender=Page)
def handle_page_saved(sender, instance, created, **kwargs):
    """
    Handle post-save actions for pages.
    """
    # Clear various caches
    cache.delete('page_list')
    cache.delete(f'page_{instance.slug}')
    
    # If page was just published, clear public caches
    if instance.status == 'published':
        cache.delete('published_pages')
        cache.delete('sitemap')
    
    # Create initial version for new pages
    if created:
        PageVersion.objects.create(
            page=instance,
            version_number=1,
            title=instance.title,
            content=instance.content,
            content_sanitized=instance.content_sanitized,
            excerpt=instance.excerpt,
            edited_by=instance.author,
            change_message="Initial version"
        )


@receiver(pre_delete, sender=Page)
def handle_page_deletion(sender, instance, **kwargs):
    """
    Handle pre-deletion cleanup for pages.
    """
    # Clear all related caches
    cache.delete(f'page_{instance.slug}')
    cache.delete('page_list')
    cache.delete('published_pages')
    
    if instance.category:
        cache.delete(f'category_{instance.category.slug}_pages')
    
    if instance.featured:
        cache.delete('featured_pages')
    
    # Note: Audit log for deletion should be created in the view
    # to capture user information
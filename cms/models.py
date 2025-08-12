"""
CMS models for content management with security features.
Includes RBAC, HTML sanitization, and audit trails.
"""

from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, RegexValidator
from django.core.exceptions import ValidationError
from django.conf import settings
from django.urls import reverse
import bleach
from django_ckeditor_5.fields import CKEditor5Field
import uuid
from datetime import datetime


class PageQuerySet(models.QuerySet):
    """Custom queryset for Page model with security filters."""
    
    def published(self):
        """Get only published pages."""
        return self.filter(
            status='published',
            publish_at__lte=timezone.now()
        )
    
    def draft(self):
        """Get only draft pages."""
        return self.filter(status='draft')
    
    def visible_to_user(self, user):
        """Get pages visible to a specific user based on permissions."""
        if user.is_superuser:
            return self
        
        if user.is_authenticated:
            # Staff can see all pages
            if user.is_staff:
                return self
            
            # Regular users see published pages and their own drafts
            from django.db.models import Q
            return self.filter(
                Q(status='published', publish_at__lte=timezone.now()) |
                Q(author=user)
            )
        
        # Anonymous users see only published pages
        return self.published()


class PageManager(models.Manager):
    """Custom manager for Page model."""
    
    def get_queryset(self):
        return PageQuerySet(self.model, using=self._db)
    
    def published(self):
        return self.get_queryset().published()
    
    def draft(self):
        return self.get_queryset().draft()
    
    def visible_to_user(self, user):
        return self.get_queryset().visible_to_user(user)


class Category(models.Model):
    """Category model for organizing pages."""
    
    name = models.CharField(
        _('category name'),
        max_length=100,
        unique=True,
        validators=[MinLengthValidator(2)]
    )
    slug = models.SlugField(
        _('slug'),
        max_length=100,
        unique=True,
        help_text=_('URL-friendly version of the name')
    )
    description = models.TextField(
        _('description'),
        blank=True,
        help_text=_('Brief description of the category')
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children'
    )
    order = models.IntegerField(
        _('display order'),
        default=0,
        help_text=_('Order in which categories are displayed')
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_('Whether this category is active')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = _('category')
        verbose_name_plural = _('categories')
        ordering = ['order', 'name']
        db_table = 'cms_categories'
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)
    
    def get_absolute_url(self):
        return reverse('cms:category_detail', kwargs={'slug': self.slug})


class Tag(models.Model):
    """Tag model for content tagging."""
    
    name = models.CharField(
        _('tag name'),
        max_length=50,
        unique=True
    )
    slug = models.SlugField(
        _('slug'),
        max_length=50,
        unique=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = _('tag')
        verbose_name_plural = _('tags')
        ordering = ['name']
        db_table = 'cms_tags'
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)


class Page(models.Model):
    """
    Main Page model with content, RBAC, and security features.
    """
    
    STATUS_CHOICES = [
        ('draft', _('Draft')),
        ('review', _('Under Review')),
        ('published', _('Published')),
        ('archived', _('Archived')),
    ]
    
    VISIBILITY_CHOICES = [
        ('public', _('Public')),
        ('authenticated', _('Authenticated Users Only')),
        ('staff', _('Staff Only')),
        ('author', _('Author Only')),
    ]
    
    # Unique identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # URL and title
    slug = models.SlugField(
        _('slug'),
        max_length=200,
        unique=True,
        validators=[
            RegexValidator(
                regex='^[a-z0-9-]+$',
                message='Slug must contain only lowercase letters, numbers, and hyphens'
            )
        ],
        help_text=_('URL-friendly version of the title')
    )
    
    title = models.CharField(
        _('title'),
        max_length=200,
        validators=[MinLengthValidator(3)],
        help_text=_('Page title (max 200 characters)')
    )
    
    # Content fields with sanitization
    content = CKEditor5Field(
        _('content'),
        config_name='default',
        help_text=_('Main page content (HTML will be sanitized)')
    )
    
    content_sanitized = models.TextField(
        _('sanitized content'),
        editable=False,
        help_text=_('Auto-sanitized version of content')
    )
    
    excerpt = models.TextField(
        _('excerpt'),
        max_length=500,
        blank=True,
        help_text=_('Brief description or summary')
    )
    
    # SEO fields
    meta_title = models.CharField(
        _('meta title'),
        max_length=70,
        blank=True,
        help_text=_('SEO meta title (defaults to page title)')
    )
    
    meta_description = models.CharField(
        _('meta description'),
        max_length=160,
        blank=True,
        help_text=_('SEO meta description')
    )
    
    meta_keywords = models.CharField(
        _('meta keywords'),
        max_length=255,
        blank=True,
        help_text=_('Comma-separated keywords')
    )
    
    # Author and ownership
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='pages',
        help_text=_('Page author/owner')
    )
    
    # Status and visibility
    status = models.CharField(
        _('status'),
        max_length=10,
        choices=STATUS_CHOICES,
        default='draft',
        db_index=True
    )
    
    visibility = models.CharField(
        _('visibility'),
        max_length=15,
        choices=VISIBILITY_CHOICES,
        default='public',
        help_text=_('Who can view this page')
    )
    
    # Publishing
    publish_at = models.DateTimeField(
        _('publish date'),
        default=timezone.now,
        db_index=True,
        help_text=_('Date and time when page becomes visible')
    )
    
    unpublish_at = models.DateTimeField(
        _('unpublish date'),
        null=True,
        blank=True,
        help_text=_('Optional: auto-unpublish at this date')
    )
    
    # Categorization
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='pages'
    )
    
    tags = models.ManyToManyField(
        Tag,
        blank=True,
        related_name='pages'
    )
    
    # Features
    featured = models.BooleanField(
        _('featured'),
        default=False,
        help_text=_('Show in featured content sections')
    )
    
    allow_comments = models.BooleanField(
        _('allow comments'),
        default=True
    )
    
    # Version control
    version = models.PositiveIntegerField(
        _('version'),
        default=1,
        editable=False
    )
    
    # Audit fields
    created_at = models.DateTimeField(
        _('created at'),
        auto_now_add=True,
        db_index=True
    )
    
    updated_at = models.DateTimeField(
        _('updated at'),
        auto_now=True
    )
    
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='page_updates',
        editable=False
    )
    
    # Statistics
    view_count = models.PositiveIntegerField(
        _('view count'),
        default=0,
        editable=False
    )
    
    # Security
    requires_auth = models.BooleanField(
        _('requires authentication'),
        default=False,
        help_text=_('Require login to view this page')
    )
    
    allowed_groups = models.ManyToManyField(
        'auth.Group',
        blank=True,
        related_name='allowed_pages',
        help_text=_('Groups that can access this page')
    )
    
    # Custom manager
    objects = PageManager()
    
    class Meta:
        verbose_name = _('page')
        verbose_name_plural = _('pages')
        ordering = ['-publish_at', '-created_at']
        db_table = 'cms_pages'
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['status', 'publish_at']),
            models.Index(fields=['author', 'status']),
            models.Index(fields=['created_at']),
        ]
        permissions = [
            ('can_publish_page', 'Can publish pages'),
            ('can_review_page', 'Can review pages'),
            ('can_feature_page', 'Can feature pages'),
        ]
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        """Override save to sanitize content and generate slug."""
        # Generate slug if not provided
        if not self.slug:
            self.slug = slugify(self.title)
            
            # Ensure unique slug
            original_slug = self.slug
            counter = 1
            while Page.objects.filter(slug=self.slug).exists():
                self.slug = f"{original_slug}-{counter}"
                counter += 1
        
        # Sanitize content
        self.content_sanitized = self.sanitize_content(self.content)
        
        # Set meta title if not provided
        if not self.meta_title:
            self.meta_title = self.title[:70]
        
        # Increment version on update
        if self.pk:
            self.version += 1
        
        super().save(*args, **kwargs)
    
    def sanitize_content(self, content):
        """
        Sanitize HTML content to prevent XSS attacks.
        Uses bleach library with strict whitelist.
        """
        # Allowed tags for rich content
        allowed_tags = [
            'p', 'br', 'span', 'div', 'section', 'article',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'strong', 'em', 'u', 's', 'mark',
            'a', 'img', 'video', 'audio', 'source',
            'ul', 'ol', 'li',
            'table', 'thead', 'tbody', 'tr', 'th', 'td',
            'blockquote', 'code', 'pre',
            'figure', 'figcaption',
        ]
        
        # Allowed attributes
        allowed_attributes = {
            '*': ['class', 'id'],
            'a': ['href', 'title', 'target', 'rel'],
            'img': ['src', 'alt', 'title', 'width', 'height'],
            'video': ['src', 'controls', 'width', 'height'],
            'audio': ['src', 'controls'],
            'source': ['src', 'type'],
        }
        
        # Allowed protocols
        allowed_protocols = ['http', 'https', 'mailto']
        
        # Sanitize with bleach
        cleaned = bleach.clean(
            content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            protocols=allowed_protocols,
            strip=True,  # Strip disallowed tags
            strip_comments=True
        )
        
        # Additional sanitization for script tags (extra safety)
        import re
        cleaned = re.sub(r'<script[^>]*>.*?</script>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'on\w+\s*=', '', cleaned, flags=re.IGNORECASE)  # Remove event handlers
        
        return cleaned
    
    def get_absolute_url(self):
        """Get the canonical URL for this page."""
        return reverse('cms:page_detail', kwargs={'slug': self.slug})
    
    def get_edit_url(self):
        """Get the edit URL for this page."""
        return reverse('cms:page_edit', kwargs={'slug': self.slug})
    
    def is_published(self):
        """Check if page is currently published."""
        now = timezone.now()
        
        if self.status != 'published':
            return False
        
        if self.publish_at > now:
            return False
        
        if self.unpublish_at and self.unpublish_at <= now:
            return False
        
        return True
    
    def can_view(self, user):
        """Check if user has permission to view this page."""
        # Superusers can view everything
        if user and user.is_superuser:
            return True
        
        # Check visibility settings
        if self.visibility == 'public' and self.is_published():
            return True
        
        if not user or not user.is_authenticated:
            return False
        
        # Check specific visibility rules
        if self.visibility == 'authenticated':
            return True
        
        if self.visibility == 'staff' and user.is_staff:
            return True
        
        if self.visibility == 'author' and self.author == user:
            return True
        
        # Check group permissions
        if self.allowed_groups.exists():
            return user.groups.filter(
                id__in=self.allowed_groups.values_list('id', flat=True)
            ).exists()
        
        # Authors can always view their own pages
        return self.author == user
    
    def can_edit(self, user):
        """Check if user has permission to edit this page."""
        if not user or not user.is_authenticated:
            return False
        
        # Superusers and staff can edit
        if user.is_superuser or user.is_staff:
            return True
        
        # Authors can edit their own pages
        return self.author == user
    
    def can_delete(self, user):
        """Check if user has permission to delete this page."""
        if not user or not user.is_authenticated:
            return False
        
        # Only superusers and authors can delete
        if user.is_superuser:
            return True
        
        # Authors can delete their own drafts
        return self.author == user and self.status == 'draft'
    
    def increment_view_count(self):
        """Increment view counter (does not trigger save signals)."""
        Page.objects.filter(pk=self.pk).update(
            view_count=models.F('view_count') + 1
        )


class PageVersion(models.Model):
    """
    Version history for pages to track changes.
    """
    
    page = models.ForeignKey(
        Page,
        on_delete=models.CASCADE,
        related_name='versions'
    )
    
    version_number = models.PositiveIntegerField()
    
    # Snapshot of page content
    title = models.CharField(max_length=200)
    content = models.TextField()
    content_sanitized = models.TextField()
    excerpt = models.TextField(blank=True)
    
    # Who made the change
    edited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )
    
    # When the change was made
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Change description
    change_message = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Brief description of changes')
    )
    
    class Meta:
        verbose_name = _('page version')
        verbose_name_plural = _('page versions')
        ordering = ['-version_number']
        db_table = 'cms_page_versions'
        unique_together = [['page', 'version_number']]
    
    def __str__(self):
        return f"{self.page.title} (v{self.version_number})"


class PageAuditLog(models.Model):
    """
    Audit log for page actions.
    """
    
    ACTION_CHOICES = [
        ('created', 'Created'),
        ('edited', 'Edited'),
        ('published', 'Published'),
        ('unpublished', 'Unpublished'),
        ('deleted', 'Deleted'),
        ('viewed', 'Viewed'),
        ('featured', 'Featured'),
        ('unfeatured', 'Unfeatured'),
    ]
    
    page = models.ForeignKey(
        Page,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_logs'
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )
    
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = _('page audit log')
        verbose_name_plural = _('page audit logs')
        ordering = ['-timestamp']
        db_table = 'cms_page_audit_logs'
        indexes = [
            models.Index(fields=['page', 'action']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.action} - {self.page} - {self.timestamp}"
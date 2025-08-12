"""
Admin configuration for CMS models with security features.
Includes safe preview, version history, and audit logging.
"""

from django.contrib import admin
from django.utils.html import format_html, mark_safe
from django.utils import timezone
from django.urls import reverse, path
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django import forms
import csv

from .models import Page, PageVersion, PageAuditLog, Category, Tag


class PageAdminForm(forms.ModelForm):
    """Custom form for Page admin with validation."""
    
    class Meta:
        model = Page
        fields = '__all__'
    
    def clean_slug(self):
        """Validate slug uniqueness."""
        slug = self.cleaned_data.get('slug')
        instance = self.instance
        
        if slug:
            # Check for duplicate slugs
            qs = Page.objects.filter(slug=slug)
            if instance.pk:
                qs = qs.exclude(pk=instance.pk)
            
            if qs.exists():
                raise forms.ValidationError('A page with this slug already exists.')
        
        return slug
    
    def clean_publish_at(self):
        """Validate publish date."""
        publish_at = self.cleaned_data.get('publish_at')
        unpublish_at = self.cleaned_data.get('unpublish_at')
        
        if unpublish_at and publish_at and unpublish_at <= publish_at:
            raise forms.ValidationError('Unpublish date must be after publish date.')
        
        return publish_at


class PageVersionInline(admin.TabularInline):
    """Inline admin for page versions."""
    model = PageVersion
    extra = 0
    readonly_fields = ('version_number', 'title', 'edited_by', 'created_at', 'change_message')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


class PageAuditLogInline(admin.TabularInline):
    """Inline admin for page audit logs."""
    model = PageAuditLog
    extra = 0
    readonly_fields = ('action', 'user', 'timestamp', 'ip_address', 'user_agent')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Page)
class PageAdmin(admin.ModelAdmin):
    """
    Admin interface for Page model with enhanced security features.
    """
    form = PageAdminForm
    
    list_display = (
        'title_with_status', 'author_link', 'category', 
        'status_badge', 'visibility_badge', 'publish_at',
        'view_count', 'featured_icon', 'actions_buttons'
    )
    
    list_filter = (
        'status', 'visibility', 'featured', 'category',
        'publish_at', 'created_at', 'author'
    )
    
    search_fields = ('title', 'slug', 'content', 'author__email')
    
    readonly_fields = (
        'id', 'content_sanitized', 'version', 'view_count',
        'created_at', 'updated_at', 'updated_by', 'preview_link'
    )
    
    prepopulated_fields = {'slug': ('title',)}
    
    filter_horizontal = ('tags', 'allowed_groups')
    
    date_hierarchy = 'publish_at'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'slug', 'category', 'tags', 'excerpt')
        }),
        ('Content', {
            'fields': ('content', 'content_sanitized', 'preview_link'),
            'classes': ('wide',)
        }),
        ('Publishing', {
            'fields': ('status', 'visibility', 'publish_at', 'unpublish_at', 
                      'featured', 'author')
        }),
        ('SEO', {
            'fields': ('meta_title', 'meta_description', 'meta_keywords'),
            'classes': ('collapse',)
        }),
        ('Security & Permissions', {
            'fields': ('requires_auth', 'allowed_groups', 'allow_comments'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('id', 'version', 'view_count', 'created_at', 
                      'updated_at', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    inlines = [PageVersionInline, PageAuditLogInline]
    
    actions = [
        'publish_pages', 'unpublish_pages', 'feature_pages',
        'unfeature_pages', 'export_pages_csv', 'duplicate_pages'
    ]
    
    def version_history(self, request, page_id):
        """View version history for a page."""
        page = get_object_or_404(Page, pk=page_id)
        versions = page.versions.all()
        
        context = {
            'page': page,
            'versions': versions,
            'title': f'Version History: {page.title}'
        }
        
        return render(request, 'admin/cms/version_history.html', context)

    def get_urls(self):
        """Add custom URLs for preview and version management."""
        urls = super().get_urls()
        custom_urls = [
            path('<uuid:page_id>/preview/',
                 self.admin_site.admin_view(self.preview_page),
                 name='cms_page_preview'),
            path('<uuid:page_id>/versions/',
                 self.admin_site.admin_view(self.version_history),
                 name='cms_page_versions'),
            path('<uuid:page_id>/restore/<int:version_id>/',
                 self.admin_site.admin_view(self.restore_version),
                 name='cms_page_restore'),
        ]
        return custom_urls + urls
    
    def title_with_status(self, obj):
        """Display title with draft indicator."""
        if obj.status == 'draft':
            return format_html(
                '<span style="color: #999;">[DRAFT] {}</span>',
                obj.title
            )
        return obj.title
    title_with_status.short_description = 'Title'
    title_with_status.admin_order_field = 'title'
    
    def author_link(self, obj):
        """Link to author's user admin page."""
        url = reverse('admin:accounts_emailuser_change', args=[obj.author.id])
        return format_html('<a href="{}">{}</a>', url, obj.author.get_display_name())
    author_link.short_description = 'Author'
    
    def status_badge(self, obj):
        """Display status as colored badge."""
        colors = {
            'draft': '#6c757d',
            'review': '#ffc107',
            'published': '#28a745',
            'archived': '#dc3545',
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            colors.get(obj.status, '#000'),
            obj.get_status_display().upper()
        )
    status_badge.short_description = 'Status'
    
    def visibility_badge(self, obj):
        """Display visibility as icon."""
        icons = {
            'public': '🌍',
            'authenticated': '🔐',
            'staff': '👔',
            'author': '👤',
        }
        return format_html(
            '{} {}',
            icons.get(obj.visibility, '❓'),
            obj.get_visibility_display()
        )
    visibility_badge.short_description = 'Visibility'
    
    def featured_icon(self, obj):
        """Display featured status as icon."""
        if obj.featured:
            return format_html('<span style="color: gold;">⭐</span>')
        return format_html('<span style="color: #ccc;">☆</span>')
    featured_icon.short_description = 'Featured'
    
    def preview_link(self, obj):
        """Generate safe preview link."""
        if obj.pk:
            url = reverse('admin:cms_page_preview', args=[obj.pk])
            return format_html(
                '<a href="{}" target="_blank" class="button">Preview Page</a>',
                url
            )
        return "Save page first to preview"
    preview_link.short_description = 'Preview'
    
    def actions_buttons(self, obj):
        """Custom action buttons."""
        buttons = []
        
        # View on site
        if obj.is_published():
            url = obj.get_absolute_url()
            buttons.append(f'<a href="{url}" target="_blank" title="View">👁</a>')
        
        # Edit
        url = reverse('admin:cms_page_change', args=[obj.pk])
        buttons.append(f'<a href="{url}" title="Edit">✏️</a>')
        
        # Version history
        url = reverse('admin:cms_page_versions', args=[obj.pk])
        buttons.append(f'<a href="{url}" title="Versions">📚</a>')
        
        return format_html(' '.join(buttons))
    actions_buttons.short_description = 'Actions'
    
    def preview_page(self, request, page_id):
        """Safe preview of page content."""
        page = get_object_or_404(Page, pk=page_id)
        
        # Check permissions
        if not page.can_view(request.user):
            messages.error(request, "You don't have permission to preview this page.")
            return redirect('admin:cms_page_changelist')
        
        # Log preview action
        PageAuditLog.objects.create(
            page=page,
            user=request.user,
            action='viewed',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
        )
        
        context = {
            'page': page,
            'is_preview': True,
            'admin_url': reverse('admin:cms_page_change', args=[page.pk])
        }
        
        return render(request, 'admin/cms/version_history.html', context)
    
    def restore_version(self, request, page_id, version_id):
        """Restore a previous version of a page."""
        page = get_object_or_404(Page, pk=page_id)
        version = get_object_or_404(PageVersion, pk=version_id, page=page)
        
        if request.method == 'POST':
            # Create new version before restoring
            PageVersion.objects.create(
                page=page,
                version_number=page.version,
                title=page.title,
                content=page.content,
                content_sanitized=page.content_sanitized,
                excerpt=page.excerpt,
                edited_by=request.user,
                change_message=f"Before restoring to v{version.version_number}"
            )
            
            # Restore content
            page.title = version.title
            page.content = version.content
            page.excerpt = version.excerpt
            page.updated_by = request.user
            page.save()
            
            # Log restoration
            PageAuditLog.objects.create(
                page=page,
                user=request.user,
                action='edited',
                details={'restored_from_version': version.version_number}
            )
            
            messages.success(
                request, 
                f'Page restored to version {version.version_number}'
            )
            return redirect('admin:cms_page_change', page.pk)
        
        context = {
            'page': page,
            'version': version,
            'title': f'Restore Version {version.version_number}'
        }
        
        return render(request, 'admin/cms/restore_version.html', context)
    
    def save_model(self, request, obj, form, change):
        """Override save to track changes and create versions."""
        if change:
            # Get original object
            original = Page.objects.get(pk=obj.pk)
            
            # Create version history
            PageVersion.objects.create(
                page=original,
                version_number=original.version,
                title=original.title,
                content=original.content,
                content_sanitized=original.content_sanitized,
                excerpt=original.excerpt,
                edited_by=request.user,
                change_message=f"Edited by {request.user}"
            )
            
            # Set updated_by
            obj.updated_by = request.user
            
            # Log edit action
            PageAuditLog.objects.create(
                page=obj,
                user=request.user,
                action='edited',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
            )
        else:
            # New page
            if not obj.author_id:
                obj.author = request.user
            
            # Log creation
            PageAuditLog.objects.create(
                page=obj,
                user=request.user,
                action='created',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
            )
        
        super().save_model(request, obj, form, change)
    
    def delete_model(self, request, obj):
        """Log deletion before deleting."""
        PageAuditLog.objects.create(
            page=None,  # Page will be deleted
            user=request.user,
            action='deleted',
            details={'page_title': obj.title, 'page_id': str(obj.id)}
        )
        super().delete_model(request, obj)
    
    # Admin Actions
    def publish_pages(self, request, queryset):
        """Publish selected pages."""
        count = 0
        for page in queryset:
            if page.status != 'published':
                page.status = 'published'
                page.save()
                
                PageAuditLog.objects.create(
                    page=page,
                    user=request.user,
                    action='published'
                )
                count += 1
        
        self.message_user(
            request, 
            f'{count} pages published successfully.',
            messages.SUCCESS
        )
    publish_pages.short_description = "Publish selected pages"
    
    def unpublish_pages(self, request, queryset):
        """Unpublish selected pages."""
        count = queryset.filter(status='published').update(status='draft')
        
        for page in queryset:
            PageAuditLog.objects.create(
                page=page,
                user=request.user,
                action='unpublished'
            )
        
        self.message_user(
            request,
            f'{count} pages unpublished.',
            messages.WARNING
        )
    unpublish_pages.short_description = "Unpublish selected pages"
    
    def feature_pages(self, request, queryset):
        """Feature selected pages."""
        count = queryset.update(featured=True)
        
        for page in queryset:
            PageAuditLog.objects.create(
                page=page,
                user=request.user,
                action='featured'
            )
        
        self.message_user(
            request,
            f'{count} pages featured.',
            messages.SUCCESS
        )
    feature_pages.short_description = "Feature selected pages"
    
    def unfeature_pages(self, request, queryset):
        """Unfeature selected pages."""
        count = queryset.update(featured=False)
        
        for page in queryset:
            PageAuditLog.objects.create(
                page=page,
                user=request.user,
                action='unfeatured'
            )
        
        self.message_user(
            request,
            f'{count} pages unfeatured.',
            messages.INFO
        )
    unfeature_pages.short_description = "Unfeature selected pages"
    
    def duplicate_pages(self, request, queryset):
        """Duplicate selected pages as drafts."""
        count = 0
        for page in queryset:
            # Create duplicate
            new_page = Page.objects.create(
                title=f"{page.title} (Copy)",
                slug=f"{page.slug}-copy-{timezone.now().timestamp()}",
                content=page.content,
                excerpt=page.excerpt,
                author=request.user,
                status='draft',
                category=page.category,
                meta_title=page.meta_title,
                meta_description=page.meta_description,
                meta_keywords=page.meta_keywords,
            )
            
            # Copy tags
            new_page.tags.set(page.tags.all())
            
            count += 1
        
        self.message_user(
            request,
            f'{count} pages duplicated as drafts.',
            messages.SUCCESS
        )
    duplicate_pages.short_description = "Duplicate selected pages"
    
    def export_pages_csv(self, request, queryset):
        """Export selected pages to CSV."""
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="pages.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Title', 'Slug', 'Author', 'Status', 'Category',
            'Publish Date', 'View Count', 'Created', 'Updated'
        ])
        
        for page in queryset:
            writer.writerow([
                page.title,
                page.slug,
                page.author.email,
                page.status,
                page.category.name if page.category else '',
                page.publish_at.strftime('%Y-%m-%d %H:%M'),
                page.view_count,
                page.created_at.strftime('%Y-%m-%d %H:%M'),
                page.updated_at.strftime('%Y-%m-%d %H:%M'),
            ])
        
        return response
    export_pages_csv.short_description = "Export to CSV"
    
    def get_queryset(self, request):
        """Filter queryset based on user permissions."""
        qs = super().get_queryset(request)
        
        # Non-superusers only see their own pages or published pages
        if not request.user.is_superuser:
            if request.user.is_staff:
                # Staff can see all pages
                return qs
            else:
                # Regular users see only their own pages
                return qs.filter(author=request.user)
        
        return qs
    
    def has_change_permission(self, request, obj=None):
        """Check if user can edit page."""
        if obj and not obj.can_edit(request.user):
            return False
        return super().has_change_permission(request, obj)
    
    def has_delete_permission(self, request, obj=None):
        """Check if user can delete page."""
        if obj and not obj.can_delete(request.user):
            return False
        return super().has_delete_permission(request, obj)
    
    


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Admin interface for categories."""
    list_display = ('name', 'slug', 'parent', 'order', 'is_active', 'page_count')
    list_filter = ('is_active', 'parent')
    search_fields = ('name', 'slug', 'description')
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['order', 'name']
    
    def page_count(self, obj):
        """Count pages in category."""
        return obj.pages.count()
    page_count.short_description = 'Pages'


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    """Admin interface for tags."""
    list_display = ('name', 'slug', 'page_count', 'created_at')
    search_fields = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}
    
    def page_count(self, obj):
        """Count pages with this tag."""
        return obj.pages.count()
    page_count.short_description = 'Pages'


@admin.register(PageAuditLog)
class PageAuditLogAdmin(admin.ModelAdmin):
    """Admin interface for audit logs."""
    list_display = ('page', 'user', 'action', 'timestamp', 'ip_address')
    list_filter = ('action', 'timestamp')
    search_fields = ('page__title', 'user__email', 'ip_address')
    readonly_fields = ('page', 'user', 'action', 'timestamp', 
                      'ip_address', 'user_agent', 'details')
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        """Prevent manual creation of audit logs."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of audit logs."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make audit logs read-only."""
        return False
    

"""
Forms for CMS page creation and editing with validation and security.
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from ckeditor5.widgets import CKEditor5Widget
import re

from .models import Page, Category, Tag


class PageForm(forms.ModelForm):
    """
    Form for creating and editing pages with security validation.
    """
    
    content = forms.CharField(
        widget=CKEditor5Widget(config_name='default'),
        label=_('Content'),
        help_text=_('Page content (HTML will be sanitized for security)')
    )
    
    tags = forms.ModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label=_('Tags')
    )
    
    class Meta:
        model = Page
        fields = [
            'title', 'slug', 'content', 'excerpt',
            'category', 'tags', 'status', 'visibility',
            'publish_at', 'unpublish_at', 'featured',
            'meta_title', 'meta_description', 'meta_keywords',
            'requires_auth', 'allowed_groups', 'allow_comments'
        ]
        
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter page title',
                'maxlength': 200
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'url-friendly-version',
                'pattern': '^[a-z0-9-]+$',
                'title': 'Only lowercase letters, numbers, and hyphens allowed'
            }),
            'excerpt': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Brief description or summary',
                'maxlength': 500
            }),
            'category': forms.Select(attrs={
                'class': 'form-control'
            }),
            'status': forms.Select(attrs={
                'class': 'form-control'
            }),
            'visibility': forms.Select(attrs={
                'class': 'form-control'
            }),
            'publish_at': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'unpublish_at': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'meta_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'SEO title (max 70 chars)',
                'maxlength': 70
            }),
            'meta_description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'SEO description (max 160 chars)',
                'maxlength': 160
            }),
            'meta_keywords': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'keyword1, keyword2, keyword3'
            }),
            'allowed_groups': forms.SelectMultiple(attrs={
                'class': 'form-control',
                'size': 5
            }),
        }
        
        help_texts = {
            'slug': _('URL-friendly version of the title. Leave blank to auto-generate.'),
            'visibility': _('Control who can see this page'),
            'featured': _('Show this page in featured sections'),
            'requires_auth': _('Users must be logged in to view this page'),
            'allowed_groups': _('Restrict access to specific user groups'),
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Set initial publish_at if creating new page
        if not self.instance.pk:
            from django.utils import timezone
            self.fields['publish_at'].initial = timezone.now()
        
        # Limit status choices based on user permissions
        if self.user and not self.user.is_staff:
            self.fields['status'].choices = [
                ('draft', 'Draft'),
                ('review', 'Under Review'),
            ]
            # Regular users can't set featured flag
            self.fields['featured'].widget = forms.HiddenInput()
            self.fields['featured'].initial = False
    
    def clean_slug(self):
        """Validate and generate slug if needed."""
        slug = self.cleaned_data.get('slug')
        
        if not slug:
            # Auto-generate from title
            title = self.cleaned_data.get('title', '')
            if title:
                slug = slugify(title)
                
                # Ensure uniqueness
                original_slug = slug
                counter = 1
                while Page.objects.filter(slug=slug).exclude(pk=self.instance.pk).exists():
                    slug = f"{original_slug}-{counter}"
                    counter += 1
        else:
            # Validate format
            if not re.match(r'^[a-z0-9-]+$', slug):
                raise ValidationError(
                    _('Slug can only contain lowercase letters, numbers, and hyphens.')
                )
            
            # Check uniqueness
            if Page.objects.filter(slug=slug).exclude(pk=self.instance.pk).exists():
                raise ValidationError(
                    _('A page with this slug already exists.')
                )
        
        return slug
    
    def clean_content(self):
        """Basic content validation."""
        content = self.cleaned_data.get('content')
        
        if not content or len(content.strip()) < 10:
            raise ValidationError(
                _('Content must be at least 10 characters long.')
            )
        
        # Check for potentially malicious patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',  # Event handlers
            r'<iframe[^>]*>.*?</iframe>',  # Unless specifically allowed
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                raise ValidationError(
                    _('Content contains potentially unsafe HTML. '
                      'Please remove any scripts or event handlers.')
                )
        
        return content
    
    def clean_unpublish_at(self):
        """Validate unpublish date."""
        publish_at = self.cleaned_data.get('publish_at')
        unpublish_at = self.cleaned_data.get('unpublish_at')
        
        if unpublish_at and publish_at and unpublish_at <= publish_at:
            raise ValidationError(
                _('Unpublish date must be after publish date.')
            )
        
        return unpublish_at
    
    def clean_meta_keywords(self):
        """Clean and validate meta keywords."""
        keywords = self.cleaned_data.get('meta_keywords', '')
        
        if keywords:
            # Split and clean keywords
            keyword_list = [k.strip() for k in keywords.split(',')]
            
            # Limit number of keywords
            if len(keyword_list) > 10:
                raise ValidationError(
                    _('Maximum 10 keywords allowed.')
                )
            
            # Rejoin cleaned keywords
            keywords = ', '.join(keyword_list)
        
        return keywords
    
    def save(self, commit=True):
        """Save page with author information."""
        page = super().save(commit=False)
        
        # Set author if creating new page
        if not page.pk and self.user:
            page.author = self.user
        
        # Set updated_by if editing
        if page.pk and self.user:
            page.updated_by = self.user
        
        if commit:
            page.save()
            self.save_m2m()  # Save many-to-many relationships
        
        return page


class PageSearchForm(forms.Form):
    """Form for searching pages."""
    
    q = forms.CharField(
        required=False,
        label=_('Search'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search pages...',
        })
    )
    
    category = forms.ModelChoiceField(
        queryset=Category.objects.filter(is_active=True),
        required=False,
        empty_label='All Categories',
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    
    status = forms.ChoiceField(
        choices=[('', 'All')] + Page.STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    
    author = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Author email or name'
        })
    )
    
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    featured = forms.BooleanField(
        required=False,
        label=_('Featured only'),
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )


class CategoryForm(forms.ModelForm):
    """Form for creating and editing categories."""
    
    class Meta:
        model = Category
        fields = ['name', 'slug', 'description', 'parent', 'order', 'is_active']
        
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Category name'
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'category-slug'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
            'parent': forms.Select(attrs={
                'class': 'form-control'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0
            }),
        }
    
    def clean_slug(self):
        """Validate slug uniqueness."""
        slug = self.cleaned_data.get('slug')
        
        if not slug:
            name = self.cleaned_data.get('name', '')
            if name:
                slug = slugify(name)
        
        # Check uniqueness
        if Category.objects.filter(slug=slug).exclude(pk=self.instance.pk).exists():
            raise ValidationError(
                _('A category with this slug already exists.')
            )
        
        return slug
    
    def clean_parent(self):
        """Prevent circular references."""
        parent = self.cleaned_data.get('parent')
        
        if parent and self.instance.pk:
            # Check if parent is not self
            if parent.pk == self.instance.pk:
                raise ValidationError(
                    _('A category cannot be its own parent.')
                )
            
            # Check for circular reference
            current = parent
            while current.parent:
                if current.parent.pk == self.instance.pk:
                    raise ValidationError(
                        _('This would create a circular reference.')
                    )
                current = current.parent
        
        return parent


class TagForm(forms.ModelForm):
    """Form for creating and editing tags."""
    
    class Meta:
        model = Tag
        fields = ['name', 'slug']
        
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Tag name'
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'tag-slug'
            }),
        }
    
    def clean_slug(self):
        """Validate slug uniqueness."""
        slug = self.cleaned_data.get('slug')
        
        if not slug:
            name = self.cleaned_data.get('name', '')
            if name:
                slug = slugify(name)
        
        # Check uniqueness
        if Tag.objects.filter(slug=slug).exclude(pk=self.instance.pk).exists():
            raise ValidationError(
                _('A tag with this slug already exists.')
            )
        
        return slug


class BulkActionForm(forms.Form):
    """Form for bulk actions on pages."""
    
    ACTION_CHOICES = [
        ('', '--- Select Action ---'),
        ('publish', 'Publish'),
        ('unpublish', 'Unpublish'),
        ('feature', 'Feature'),
        ('unfeature', 'Unfeature'),
        ('delete', 'Delete'),
        ('change_category', 'Change Category'),
        ('add_tags', 'Add Tags'),
        ('remove_tags', 'Remove Tags'),
    ]
    
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    
    pages = forms.ModelMultipleChoiceField(
        queryset=Page.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True
    )
    
    category = forms.ModelChoiceField(
        queryset=Category.objects.filter(is_active=True),
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    
    tags = forms.ModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple
    )
    
    def clean(self):
        """Validate action-specific fields."""
        cleaned_data = super().clean()
        action = cleaned_data.get('action')
        
        if action == 'change_category' and not cleaned_data.get('category'):
            raise ValidationError(
                _('Please select a category.')
            )
        
        if action in ['add_tags', 'remove_tags'] and not cleaned_data.get('tags'):
            raise ValidationError(
                _('Please select tags.')
            )
        
        return cleaned_data
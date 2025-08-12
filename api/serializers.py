"""
Serializers for REST API with field-level security and validation.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re

from apps.cms.models import Page, PageVersion, Category, Tag, PageAuditLog
from apps.accounts.models import SecurityAuditLog


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    User serializer with limited field exposure for security.
    """
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 
                 'full_name', 'display_name', 'date_joined']
        read_only_fields = ['id', 'email', 'date_joined']
    
    def get_full_name(self, obj):
        """Get user's full name."""
        return obj.get_full_name()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration via API.
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = ['email', 'password', 'password2', 
                 'first_name', 'last_name']
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }
    
    def validate_email(self, value):
        """Validate email uniqueness and format."""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "A user with this email already exists."
            )
        
        # Check for disposable email domains
        disposable_domains = [
            'tempmail.com', 'throwaway.email', '10minutemail.com',
            'guerrillamail.com', 'mailinator.com'
        ]
        domain = value.split('@')[-1]
        if domain in disposable_domains:
            raise serializers.ValidationError(
                "Please use a permanent email address."
            )
        
        return value.lower()
    
    def validate(self, attrs):
        """Validate passwords match."""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({
                'password': "Password fields didn't match."
            })
        
        return attrs
    
    def create(self, validated_data):
        """Create user with security defaults."""
        validated_data.pop('password2')
        
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            # Security: Require email verification
            is_active=False,
            email_verified=False
        )
        
        # Log registration
        SecurityAuditLog.objects.create(
            user=user,
            action='USER_CREATED',
            details={'source': 'api_registration'}
        )
        
        return user


class CategorySerializer(serializers.ModelSerializer):
    """
    Serializer for categories.
    """
    page_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description', 
                 'parent', 'order', 'page_count']
        read_only_fields = ['slug']
    
    def get_page_count(self, obj):
        """Get number of published pages in category."""
        return obj.pages.filter(status='published').count()


class TagSerializer(serializers.ModelSerializer):
    """
    Serializer for tags.
    """
    page_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Tag
        fields = ['id', 'name', 'slug', 'page_count']
        read_only_fields = ['slug']
    
    def get_page_count(self, obj):
        """Get number of published pages with tag."""
        return obj.pages.filter(status='published').count()


class PageListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for page listings.
    """
    author = UserSerializer(read_only=True)
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    url = serializers.SerializerMethodField()
    
    class Meta:
        model = Page
        fields = ['id', 'slug', 'title', 'excerpt', 'author',
                 'category', 'tags', 'status', 'featured',
                 'publish_at', 'view_count', 'url']
        read_only_fields = ['id', 'slug', 'view_count']
    
    def get_url(self, obj):
        """Get page URL."""
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(obj.get_absolute_url())
        return obj.get_absolute_url()


class PageDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for single page view.
    """
    author = UserSerializer(read_only=True)
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    content_safe = serializers.SerializerMethodField()
    can_edit = serializers.SerializerMethodField()
    can_delete = serializers.SerializerMethodField()
    related_pages = serializers.SerializerMethodField()
    
    class Meta:
        model = Page
        fields = ['id', 'slug', 'title', 'content_safe', 'excerpt',
                 'author', 'category', 'tags', 'status', 'visibility',
                 'featured', 'publish_at', 'unpublish_at',
                 'meta_title', 'meta_description', 'meta_keywords',
                 'created_at', 'updated_at', 'view_count',
                 'can_edit', 'can_delete', 'related_pages']
        read_only_fields = ['id', 'slug', 'created_at', 'updated_at', 
                           'view_count', 'content_safe']
    
    def get_content_safe(self, obj):
        """Return sanitized content."""
        return obj.content_sanitized
    
    def get_can_edit(self, obj):
        """Check if current user can edit."""
        request = self.context.get('request')
        if request and request.user:
            return obj.can_edit(request.user)
        return False
    
    def get_can_delete(self, obj):
        """Check if current user can delete."""
        request = self.context.get('request')
        if request and request.user:
            return obj.can_delete(request.user)
        return False
    
    def get_related_pages(self, obj):
        """Get related pages."""
        if obj.category:
            related = Page.objects.published().filter(
                category=obj.category
            ).exclude(pk=obj.pk)[:5]
            return PageListSerializer(related, many=True, 
                                     context=self.context).data
        return []


class PageCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating and updating pages.
    """
    tags = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Tag.objects.all(),
        required=False
    )
    
    class Meta:
        model = Page
        fields = ['title', 'slug', 'content', 'excerpt',
                 'category', 'tags', 'status', 'visibility',
                 'featured', 'publish_at', 'unpublish_at',
                 'meta_title', 'meta_description', 'meta_keywords',
                 'requires_auth', 'allow_comments']
        
    def validate_slug(self, value):
        """Validate slug format and uniqueness."""
        if value:
            # Check format
            if not re.match(r'^[a-z0-9-]+$', value):
                raise serializers.ValidationError(
                    "Slug can only contain lowercase letters, numbers, and hyphens."
                )
            
            # Check uniqueness (exclude current instance if updating)
            qs = Page.objects.filter(slug=value)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            
            if qs.exists():
                raise serializers.ValidationError(
                    "A page with this slug already exists."
                )
        
        return value
    
    def validate_content(self, value):
        """Validate content for dangerous patterns."""
        if not value or len(value.strip()) < 10:
            raise serializers.ValidationError(
                "Content must be at least 10 characters long."
            )
        
        # Check for potentially malicious patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',  # Event handlers
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                raise serializers.ValidationError(
                    "Content contains potentially unsafe HTML."
                )
        
        return value
    
    def validate_status(self, value):
        """Validate status based on user permissions."""
        request = self.context.get('request')
        if request and request.user:
            # Non-staff can only set draft or review
            if not request.user.is_staff:
                if value not in ['draft', 'review']:
                    raise serializers.ValidationError(
                        "You don't have permission to publish pages."
                    )
        
        return value
    
    def validate(self, attrs):
        """Cross-field validation."""
        publish_at = attrs.get('publish_at')
        unpublish_at = attrs.get('unpublish_at')
        
        if unpublish_at and publish_at and unpublish_at <= publish_at:
            raise serializers.ValidationError({
                'unpublish_at': "Unpublish date must be after publish date."
            })
        
        return attrs
    
    def create(self, validated_data):
        """Create page with author assignment."""
        tags = validated_data.pop('tags', [])
        
        # Set author from request
        request = self.context.get('request')
        if request and request.user:
            validated_data['author'] = request.user
        
        page = Page.objects.create(**validated_data)
        
        # Set tags
        if tags:
            page.tags.set(tags)
        
        # Log creation
        if request and request.user:
            PageAuditLog.objects.create(
                page=page,
                user=request.user,
                action='created',
                details={'source': 'api'}
            )
        
        return page
    
    def update(self, instance, validated_data):
        """Update page with version tracking."""
        tags = validated_data.pop('tags', None)
        
        # Create version before update
        request = self.context.get('request')
        if request and request.user:
            PageVersion.objects.create(
                page=instance,
                version_number=instance.version,
                title=instance.title,
                content=instance.content,
                content_sanitized=instance.content_sanitized,
                excerpt=instance.excerpt,
                edited_by=request.user,
                change_message="Updated via API"
            )
            
            # Set updated_by
            instance.updated_by = request.user
        
        # Update fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        
        # Update tags if provided
        if tags is not None:
            instance.tags.set(tags)
        
        # Log update
        if request and request.user:
            PageAuditLog.objects.create(
                page=instance,
                user=request.user,
                action='edited',
                details={'source': 'api'}
            )
        
        return instance


class PageVersionSerializer(serializers.ModelSerializer):
    """
    Serializer for page versions.
    """
    edited_by = UserSerializer(read_only=True)
    
    class Meta:
        model = PageVersion
        fields = ['id', 'version_number', 'title', 'excerpt',
                 'edited_by', 'created_at', 'change_message']
        read_only_fields = '__all__'


class PageStatsSerializer(serializers.Serializer):
    """
    Serializer for page statistics.
    """
    total_pages = serializers.IntegerField()
    published_pages = serializers.IntegerField()
    draft_pages = serializers.IntegerField()
    total_views = serializers.IntegerField()
    categories = serializers.IntegerField()
    tags = serializers.IntegerField()
    authors = serializers.IntegerField()
    
    class Meta:
        fields = '__all__'


class BulkActionSerializer(serializers.Serializer):
    """
    Serializer for bulk actions on pages.
    """
    action = serializers.ChoiceField(
        choices=['publish', 'unpublish', 'feature', 
                'unfeature', 'delete']
    )
    page_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=100
    )
    
    def validate_page_ids(self, value):
        """Validate pages exist and user has permission."""
        request = self.context.get('request')
        if not request or not request.user:
            raise serializers.ValidationError("Authentication required.")
        
        # Get pages
        pages = Page.objects.filter(id__in=value)
        
        if pages.count() != len(value):
            raise serializers.ValidationError(
                "Some pages do not exist."
            )
        
        # Check permissions
        for page in pages:
            if not page.can_edit(request.user):
                raise serializers.ValidationError(
                    f"You don't have permission to edit page: {page.title}"
                )
        
        return value


class SearchSerializer(serializers.Serializer):
    """
    Serializer for search parameters.
    """
    q = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=200
    )
    category = serializers.PrimaryKeyRelatedField(
        queryset=Category.objects.filter(is_active=True),
        required=False
    )
    tags = serializers.PrimaryKeyRelatedField(
        queryset=Tag.objects.all(),
        many=True,
        required=False
    )
    status = serializers.ChoiceField(
        choices=Page.STATUS_CHOICES,
        required=False
    )
    featured = serializers.BooleanField(required=False)
    author = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        required=False
    )
    date_from = serializers.DateField(required=False)
    date_to = serializers.DateField(required=False)
    ordering = serializers.ChoiceField(
        choices=['title', '-title', 'publish_at', '-publish_at',
                'view_count', '-view_count', 'created_at', '-created_at'],
        default='-publish_at',
        required=False
    )
    
    def validate(self, attrs):
        """Validate date range."""
        date_from = attrs.get('date_from')
        date_to = attrs.get('date_to')
        
        if date_from and date_to and date_from > date_to:
            raise serializers.ValidationError({
                'date_to': "End date must be after start date."
            })
        
        return attrs
"""
REST API views with JWT authentication and permissions.
"""

from rest_framework import generics, viewsets, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import (
    IsAuthenticated, IsAuthenticatedOrReadOnly, AllowAny
)
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework_simplejwt.views import (
    TokenObtainPairView, TokenRefreshView, TokenVerifyView
)
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models import Q, Count, Sum
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from django_filters.rest_framework import DjangoFilterBackend
import uuid

from apps.cms.models import Page, PageVersion, Category, Tag, PageAuditLog
from apps.accounts.models import EmailUser, SecurityAuditLog
from .serializers import (
    UserSerializer, UserRegistrationSerializer,
    CategorySerializer, TagSerializer,
    PageListSerializer, PageDetailSerializer,
    PageCreateUpdateSerializer, PageVersionSerializer,
    PageStatsSerializer, BulkActionSerializer, SearchSerializer
)
from .permissions import IsOwnerOrReadOnly, IsStaffOrReadOnly


class StandardResultsSetPagination(PageNumberPagination):
    """Standard pagination for API responses."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT token obtain view with additional validation.
    """
    throttle_classes = [AnonRateThrottle]
    
    def post(self, request, *args, **kwargs):
        """Override to add security logging."""
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Log successful login
            email = request.data.get('email', '').lower()
            try:
                user = EmailUser.objects.get(email__iexact=email)
                SecurityAuditLog.objects.create(
                    user=user,
                    action='LOGIN_SUCCESS',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:255],
                    details={'method': 'jwt_api'}
                )
            except EmailUser.DoesNotExist:
                pass
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserRegistrationView(generics.CreateAPIView):
    """
    User registration endpoint.
    """
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def create(self, request, *args, **kwargs):
        """Create user and return tokens."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.save()
        
        # Note: User is inactive until email verification
        # In production, send verification email here
        
        return Response({
            'user': UserSerializer(user).data,
            'message': 'Registration successful. Please check your email to verify your account.'
        }, status=status.HTTP_201_CREATED)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    User profile endpoint for authenticated users.
    """
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        """Return current user."""
        return self.request.user


class PageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Page CRUD operations.
    """
    queryset = Page.objects.all()
    permission_classes = [IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'category', 'featured', 'author']
    search_fields = ['title', 'content', 'excerpt']
    ordering_fields = ['title', 'publish_at', 'view_count', 'created_at']
    ordering = ['-publish_at']
    lookup_field = 'slug'
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return PageListSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return PageCreateUpdateSerializer
        else:
            return PageDetailSerializer
    
    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset()
        
        # Filter based on user
        if self.request.user.is_authenticated:
            if self.request.user.is_staff:
                # Staff sees all
                return queryset
            else:
                # Users see published pages and their own
                from django.db.models import Q
                return queryset.filter(
                    Q(status='published', publish_at__lte=timezone.now()) |
                    Q(author=self.request.user)
                )
        else:
            # Anonymous users see only published pages
            return queryset.filter(
                status='published',
                publish_at__lte=timezone.now()
            )
    
    def retrieve(self, request, *args, **kwargs):
        """Override to increment view count and log."""
        instance = self.get_object()
        
        # Check permissions
        if not instance.can_view(request.user):
            return Response(
                {'detail': 'You do not have permission to view this page.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Increment view count (not for author)
        if request.user != instance.author:
            instance.increment_view_count()
        
        # Log view
        if request.user.is_authenticated:
            PageAuditLog.objects.create(
                page=instance,
                user=request.user,
                action='viewed',
                details={'source': 'api'}
            )
        
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    def perform_create(self, serializer):
        """Set author on creation."""
        serializer.save(author=self.request.user)
    
    def perform_update(self, serializer):
        """Add updated_by on update."""
        serializer.save(updated_by=self.request.user)
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def publish(self, request, slug=None):
        """Quick publish action."""
        page = self.get_object()
        
        if not page.can_edit(request.user):
            return Response(
                {'detail': 'You do not have permission to publish this page.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        page.status = 'published'
        page.publish_at = timezone.now()
        page.save()
        
        PageAuditLog.objects.create(
            page=page,
            user=request.user,
            action='published',
            details={'source': 'api'}
        )
        
        return Response({'status': 'Page published successfully'})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def unpublish(self, request, slug=None):
        """Quick unpublish action."""
        page = self.get_object()
        
        if not page.can_edit(request.user):
            return Response(
                {'detail': 'You do not have permission to unpublish this page.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        page.status = 'draft'
        page.save()
        
        PageAuditLog.objects.create(
            page=page,
            user=request.user,
            action='unpublished',
            details={'source': 'api'}
        )
        
        return Response({'status': 'Page unpublished successfully'})
    
    @action(detail=True, methods=['get'])
    def versions(self, request, slug=None):
        """Get version history for a page."""
        page = self.get_object()
        
        # Only author and staff can see versions
        if not (request.user == page.author or request.user.is_staff):
            return Response(
                {'detail': 'You do not have permission to view version history.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        versions = page.versions.all()
        serializer = PageVersionSerializer(versions, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def bulk_action(self, request):
        """Perform bulk actions on multiple pages."""
        serializer = BulkActionSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        action_type = serializer.validated_data['action']
        page_ids = serializer.validated_data['page_ids']
        
        pages = Page.objects.filter(id__in=page_ids)
        count = 0
        
        for page in pages:
            if not page.can_edit(request.user):
                continue
            
            if action_type == 'publish':
                page.status = 'published'
                page.save()
            elif action_type == 'unpublish':
                page.status = 'draft'
                page.save()
            elif action_type == 'feature':
                page.featured = True
                page.save()
            elif action_type == 'unfeature':
                page.featured = False
                page.save()
            elif action_type == 'delete':
                if page.can_delete(request.user):
                    page.delete()
            
            count += 1
            
            # Log action
            if action_type != 'delete':
                PageAuditLog.objects.create(
                    page=page,
                    user=request.user,
                    action=action_type.replace('un', 'un') if 'un' in action_type else action_type + 'ed',
                    details={'source': 'api_bulk'}
                )
        
        return Response({
            'status': f'{count} pages processed successfully'
        })


class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for categories (read-only).
    """
    queryset = Category.objects.filter(is_active=True)
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]
    lookup_field = 'slug'
    
    @action(detail=True, methods=['get'])
    def pages(self, request, slug=None):
        """Get pages in this category."""
        category = self.get_object()
        pages = Page.objects.published().filter(category=category)
        
        paginator = StandardResultsSetPagination()
        result_page = paginator.paginate_queryset(pages, request)
        serializer = PageListSerializer(result_page, many=True,
                                       context={'request': request})
        return paginator.get_paginated_response(serializer.data)


class TagViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for tags (read-only).
    """
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [AllowAny]
    lookup_field = 'slug'
    
    @action(detail=True, methods=['get'])
    def pages(self, request, slug=None):
        """Get pages with this tag."""
        tag = self.get_object()
        pages = Page.objects.published().filter(tags=tag)
        
        paginator = StandardResultsSetPagination()
        result_page = paginator.paginate_queryset(pages, request)
        serializer = PageListSerializer(result_page, many=True,
                                       context={'request': request})
        return paginator.get_paginated_response(serializer.data)


class SearchView(APIView):
    """
    Advanced search endpoint with filtering.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Search pages with filters."""
        serializer = SearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Base queryset
        queryset = Page.objects.published()
        
        # Apply filters
        data = serializer.validated_data
        
        # Text search
        q = data.get('q')
        if q:
            queryset = queryset.filter(
                Q(title__icontains=q) |
                Q(content__icontains=q) |
                Q(excerpt__icontains=q)
            )
        
        # Category filter
        if data.get('category'):
            queryset = queryset.filter(category=data['category'])
        
        # Tags filter
        if data.get('tags'):
            queryset = queryset.filter(tags__in=data['tags']).distinct()
        
        # Status filter
        if data.get('status'):
            queryset = queryset.filter(status=data['status'])
        
        # Featured filter
        if data.get('featured') is not None:
            queryset = queryset.filter(featured=data['featured'])
        
        # Author filter
        if data.get('author'):
            queryset = queryset.filter(author=data['author'])
        
        # Date range
        if data.get('date_from'):
            queryset = queryset.filter(publish_at__date__gte=data['date_from'])
        
        if data.get('date_to'):
            queryset = queryset.filter(publish_at__date__lte=data['date_to'])
        
        # Ordering
        ordering = data.get('ordering', '-publish_at')
        queryset = queryset.order_by(ordering)
        
        # Paginate results
        paginator = StandardResultsSetPagination()
        result_page = paginator.paginate_queryset(queryset, request)
        serializer = PageListSerializer(result_page, many=True,
                                       context={'request': request})
        
        return paginator.get_paginated_response(serializer.data)


class StatsView(APIView):
    """
    Statistics endpoint for dashboard.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get content statistics."""
        # Cache stats for 5 minutes
        cache_key = f'api_stats_{request.user.id}'
        stats = cache.get(cache_key)
        
        if not stats:
            # Calculate stats
            if request.user.is_staff:
                # Staff sees all stats
                stats = {
                    'total_pages': Page.objects.count(),
                    'published_pages': Page.objects.filter(status='published').count(),
                    'draft_pages': Page.objects.filter(status='draft').count(),
                    'total_views': Page.objects.aggregate(Sum('view_count'))['view_count__sum'] or 0,
                    'categories': Category.objects.filter(is_active=True).count(),
                    'tags': Tag.objects.count(),
                    'authors': EmailUser.objects.filter(pages__isnull=False).distinct().count(),
                }
            else:
                # Regular users see their own stats
                user_pages = Page.objects.filter(author=request.user)
                stats = {
                    'total_pages': user_pages.count(),
                    'published_pages': user_pages.filter(status='published').count(),
                    'draft_pages': user_pages.filter(status='draft').count(),
                    'total_views': user_pages.aggregate(Sum('view_count'))['view_count__sum'] or 0,
                    'categories': Category.objects.filter(is_active=True).count(),
                    'tags': Tag.objects.count(),
                    'authors': 1,
                }
            
            cache.set(cache_key, stats, 300)  # Cache for 5 minutes
        
        serializer = PageStatsSerializer(stats)
        return Response(serializer.data)


class FeaturedPagesView(generics.ListAPIView):
    """
    Featured pages endpoint.
    """
    serializer_class = PageListSerializer
    permission_classes = [AllowAny]
    pagination_class = None  # No pagination for featured
    
    def get_queryset(self):
        """Get featured published pages."""
        # Cache featured pages
        cache_key = 'api_featured_pages'
        pages = cache.get(cache_key)
        
        if pages is None:
            pages = Page.objects.published().filter(featured=True)[:10]
            cache.set(cache_key, pages, 300)  # Cache for 5 minutes
        
        return pages


class MyPagesView(generics.ListAPIView):
    """
    User's own pages endpoint.
    """
    serializer_class = PageListSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['title', 'publish_at', 'created_at', 'updated_at']
    ordering = ['-updated_at']
    
    def get_queryset(self):
        """Get current user's pages."""
        return Page.objects.filter(author=self.request.user)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_root(request):
    """
    API root endpoint with available endpoints.
    """
    return Response({
        'message': 'SecureCMS API v1',
        'endpoints': {
            'auth': {
                'login': request.build_absolute_uri('/api/v1/auth/login/'),
                'refresh': request.build_absolute_uri('/api/v1/auth/refresh/'),
                'verify': request.build_absolute_uri('/api/v1/auth/verify/'),
                'register': request.build_absolute_uri('/api/v1/auth/register/'),
            },
            'pages': {
                'list': request.build_absolute_uri('/api/v1/pages/'),
                'featured': request.build_absolute_uri('/api/v1/pages/featured/'),
                'my_pages': request.build_absolute_uri('/api/v1/pages/my/'),
                'search': request.build_absolute_uri('/api/v1/search/'),
            },
            'categories': request.build_absolute_uri('/api/v1/categories/'),
            'tags': request.build_absolute_uri('/api/v1/tags/'),
            'stats': request.build_absolute_uri('/api/v1/stats/'),
            'profile': request.build_absolute_uri('/api/v1/profile/'),
        },
        'documentation': request.build_absolute_uri('/api/v1/docs/'),
        'version': '1.0.0',
        'authentication': 'JWT Bearer Token',
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint for monitoring.
    """
    try:
        # Check database connection
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        # Check cache
        cache.set('health_check', 'ok', 1)
        cache_status = cache.get('health_check') == 'ok'
        
        return Response({
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'database': 'connected',
            'cache': 'connected' if cache_status else 'disconnected',
            'version': '1.0.0',
        })
    except Exception as e:
        return Response({
            'status': 'unhealthy',
            'timestamp': timezone.now().isoformat(),
            'error': str(e),
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
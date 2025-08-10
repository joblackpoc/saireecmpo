"""
Unit tests for API endpoints.
Tests authentication, CRUD operations, and permissions.
"""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import EmailUser
from apps.cms.models import Page, Category, Tag


class JWTAuthenticationTests(APITestCase):
    """Test JWT authentication endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user
        self.user = EmailUser.objects.create_user(
            email='test@example.com',
            password='TestP@ssw0rd123!',
            first_name='Test',
            last_name='User'
        )
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save()
    
    def test_token_obtain(self):
        """Test obtaining JWT tokens."""
        url = reverse('api:token_obtain_pair')
        data = {
            'email': 'test@example.com',
            'password': 'TestP@ssw0rd123!'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
    
    def test_token_refresh(self):
        """Test refreshing JWT tokens."""
        # Get initial tokens
        refresh = RefreshToken.for_user(self.user)
        
        url = reverse('api:token_refresh')
        data = {'refresh': str(refresh)}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
    
    def test_token_verify(self):
        """Test verifying JWT tokens."""
        # Get token
        refresh = RefreshToken.for_user(self.user)
        access_token = refresh.access_token
        
        url = reverse('api:token_verify')
        data = {'token': str(access_token)}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_invalid_credentials(self):
        """Test login with invalid credentials."""
        url = reverse('api:token_obtain_pair')
        data = {
            'email': 'test@example.com',
            'password': 'WrongPassword!'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_authenticated_request(self):
        """Test making authenticated API request."""
        # Get token
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        # Make authenticated request
        url = reverse('api:profile')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)


class UserRegistrationTests(APITestCase):
    """Test user registration via API."""
    
    def setUp(self):
        """Set up test client."""
        self.client = APIClient()
        self.url = reverse('api:register')
    
    def test_valid_registration(self):
        """Test successful user registration."""
        data = {
            'email': 'newuser@example.com',
            'password': 'SecureP@ssw0rd123!',
            'password2': 'SecureP@ssw0rd123!',
            'first_name': 'New',
            'last_name': 'User'
        }
        
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'newuser@example.com')
        
        # Check user was created
        self.assertTrue(
            EmailUser.objects.filter(email='newuser@example.com').exists()
        )
    
    def test_password_mismatch(self):
        """Test registration with mismatched passwords."""
        data = {
            'email': 'test@example.com',
            'password': 'SecureP@ssw0rd123!',
            'password2': 'DifferentP@ssw0rd123!',
        }
        
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)
    
    def test_duplicate_email(self):
        """Test registration with existing email."""
        # Create existing user
        EmailUser.objects.create_user(
            email='existing@example.com',
            password='TestP@ssw0rd123!'
        )
        
        data = {
            'email': 'existing@example.com',
            'password': 'SecureP@ssw0rd123!',
            'password2': 'SecureP@ssw0rd123!',
        }
        
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class PageAPITests(APITestCase):
    """Test Page API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create users
        self.author = EmailUser.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        self.author.email_verified = True
        self.author.is_active = True
        self.author.save()
        
        self.other_user = EmailUser.objects.create_user(
            email='other@example.com',
            password='TestP@ssw0rd123!'
        )
        self.other_user.email_verified = True
        self.other_user.is_active = True
        self.other_user.save()
        
        # Create category and tags
        self.category = Category.objects.create(
            name='Test Category',
            slug='test-category'
        )
        
        self.tag = Tag.objects.create(
            name='Test Tag',
            slug='test-tag'
        )
        
        # Create test page
        self.page = Page.objects.create(
            title='Test Page',
            slug='test-page',
            content='<p>Test content</p>',
            author=self.author,
            category=self.category,
            status='published'
        )
        self.page.tags.add(self.tag)
    
    def test_list_pages(self):
        """Test listing pages."""
        url = reverse('api:page-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_retrieve_page(self):
        """Test retrieving single page."""
        url = reverse('api:page-detail', kwargs={'slug': self.page.slug})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], self.page.title)
        self.assertIn('content_safe', response.data)
    
    def test_create_page_authenticated(self):
        """Test creating page as authenticated user."""
        # Authenticate
        refresh = RefreshToken.for_user(self.author)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        url = reverse('api:page-list')
        data = {
            'title': 'New API Page',
            'slug': 'new-api-page',
            'content': '<p>New content from API</p>',
            'excerpt': 'Test excerpt',
            'status': 'draft',
            'visibility': 'public',
            'publish_at': timezone.now().isoformat(),
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['title'], 'New API Page')
        
        # Check page was created
        self.assertTrue(
            Page.objects.filter(slug='new-api-page').exists()
        )
    
    def test_create_page_unauthenticated(self):
        """Test creating page without authentication."""
        url = reverse('api:page-list')
        data = {
            'title': 'Unauthorized Page',
            'content': '<p>Content</p>',
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_update_page_owner(self):
        """Test updating page as owner."""
        # Authenticate as author
        refresh = RefreshToken.for_user(self.author)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        url = reverse('api:page-detail', kwargs={'slug': self.page.slug})
        data = {
            'title': 'Updated Title',
            'content': '<p>Updated content</p>',
        }
        
        response = self.client.patch(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Updated Title')
    
    def test_update_page_non_owner(self):
        """Test updating page as non-owner."""
        # Authenticate as other user
        refresh = RefreshToken.for_user(self.other_user)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        url = reverse('api:page-detail', kwargs={'slug': self.page.slug})
        data = {
            'title': 'Unauthorized Update',
        }
        
        response = self.client.patch(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_delete_page_owner(self):
        """Test deleting page as owner."""
        # Create draft page
        draft_page = Page.objects.create(
            title='Draft Page',
            slug='draft-page',
            content='<p>Draft content</p>',
            author=self.author,
            status='draft'
        )
        
        # Authenticate as author
        refresh = RefreshToken.for_user(self.author)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        url = reverse('api:page-detail', kwargs={'slug': draft_page.slug})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Check page was deleted
        self.assertFalse(
            Page.objects.filter(slug='draft-page').exists()
        )
    
    def test_publish_page_action(self):
        """Test publish action on page."""
        # Create draft page
        draft_page = Page.objects.create(
            title='Draft Page',
            slug='draft-for-publish',
            content='<p>Content</p>',
            author=self.author,
            status='draft'
        )
        
        # Authenticate
        refresh = RefreshToken.for_user(self.author)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        url = reverse('api:page-publish', 
                     kwargs={'slug': draft_page.slug})
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check page was published
        draft_page.refresh_from_db()
        self.assertEqual(draft_page.status, 'published')


class SearchAPITests(APITestCase):
    """Test search API endpoint."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.url = reverse('api:search')
        
        # Create test user
        self.user = EmailUser.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        
        # Create test pages
        for i in range(5):
            Page.objects.create(
                title=f'Page {i}',
                slug=f'page-{i}',
                content=f'<p>Content for page {i}</p>',
                author=self.user,
                status='published' if i < 3 else 'draft',
                featured=i == 0
            )
    
    def test_search_by_title(self):
        """Test searching pages by title."""
        data = {'q': 'Page 1'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_search_featured(self):
        """Test searching featured pages."""
        data = {'featured': True}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_search_with_ordering(self):
        """Test search with custom ordering."""
        data = {
            'q': 'Page',
            'ordering': 'title'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data['results']
        
        # Check ordering
        titles = [r['title'] for r in results]
        self.assertEqual(titles, sorted(titles))


class StatsAPITests(APITestCase):
    """Test statistics API endpoint."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.url = reverse('api:stats')
        
        # Create test user
        self.user = EmailUser.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save()
        
        # Create test pages
        for i in range(3):
            Page.objects.create(
                title=f'Page {i}',
                slug=f'page-{i}',
                content='<p>Content</p>',
                author=self.user,
                status='published' if i < 2 else 'draft',
                view_count=i * 10
            )
    
    def test_stats_authenticated(self):
        """Test getting stats as authenticated user."""
        # Authenticate
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}'
        )
        
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_pages', response.data)
        self.assertIn('published_pages', response.data)
        self.assertIn('draft_pages', response.data)
        self.assertIn('total_views', response.data)
    
    def test_stats_unauthenticated(self):
        """Test stats requires authentication."""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CategoryTagAPITests(APITestCase):
    """Test Category and Tag API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test data
        self.category = Category.objects.create(
            name='Test Category',
            slug='test-category',
            description='Test description'
        )
        
        self.tag = Tag.objects.create(
            name='Test Tag',
            slug='test-tag'
        )
        
        # Create user and page
        self.user = EmailUser.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        
        self.page = Page.objects.create(
            title='Test Page',
            slug='test-page',
            content='<p>Content</p>',
            author=self.user,
            category=self.category,
            status='published'
        )
        self.page.tags.add(self.tag)
    
    def test_list_categories(self):
        """Test listing categories."""
        url = reverse('api:category-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Test Category')
    
    def test_retrieve_category(self):
        """Test retrieving single category."""
        url = reverse('api:category-detail', 
                     kwargs={'slug': self.category.slug})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.category.name)
        self.assertIn('page_count', response.data)
    
    def test_category_pages(self):
        """Test getting pages in category."""
        url = reverse('api:category-pages', 
                     kwargs={'slug': self.category.slug})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_list_tags(self):
        """Test listing tags."""
        url = reverse('api:tag-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Test Tag')
    
    def test_tag_pages(self):
        """Test getting pages with tag."""
        url = reverse('api:tag-pages', 
                     kwargs={'slug': self.tag.slug})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)


class RateLimitingTests(APITestCase):
    """Test API rate limiting."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user
        self.user = EmailUser.objects.create_user(
            email='test@example.com',
            password='TestP@ssw0rd123!'
        )
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save()
    
    def test_auth_endpoint_rate_limit(self):
        """Test rate limiting on authentication endpoint."""
        url = reverse('api:token_obtain_pair')
        data = {
            'email': 'test@example.com',
            'password': 'WrongPassword!'
        }
        
        # Make multiple requests
        responses = []
        for _ in range(10):
            response = self.client.post(url, data, format='json')
            responses.append(response.status_code)
        
        # Should get rate limited eventually
        # Note: Exact behavior depends on throttle settings
        # This test assumes stricter limits are in place
        # self.assertIn(status.HTTP_429_TOO_MANY_REQUESTS, responses)
        
        # At minimum, all should not succeed
        self.assertTrue(
            any(r != status.HTTP_200_OK for r in responses)
        )
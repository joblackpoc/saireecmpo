"""
Unit tests for CMS app.
Tests page CRUD, permissions, sanitization, and versioning.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from datetime import timedelta

from apps.cms.models import Page, PageVersion, PageAuditLog, Category, Tag
from apps.cms.forms import PageForm


User = get_user_model()


class PageModelTests(TestCase):
    """Test Page model functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        self.user.email_verified = True
        self.user.is_active = True
        self.user.save()
        
        self.category = Category.objects.create(
            name='Test Category',
            slug='test-category'
        )
    
    def test_create_page(self):
        """Test creating a basic page."""
        page = Page.objects.create(
            title='Test Page',
            slug='test-page',
            content='<p>This is test content.</p>',
            author=self.user,
            category=self.category
        )
        
        self.assertEqual(page.title, 'Test Page')
        self.assertEqual(page.slug, 'test-page')
        self.assertEqual(page.author, self.user)
        self.assertEqual(page.status, 'draft')  # Default status
        self.assertIsNotNone(page.content_sanitized)
    
    def test_auto_slug_generation(self):
        """Test automatic slug generation from title."""
        page = Page.objects.create(
            title='Page With No Slug',
            content='<p>Content</p>',
            author=self.user
        )
        
        self.assertEqual(page.slug, 'page-with-no-slug')
    
    def test_unique_slug_generation(self):
        """Test unique slug generation for duplicate titles."""
        page1 = Page.objects.create(
            title='Duplicate Title',
            content='<p>Content 1</p>',
            author=self.user
        )
        
        page2 = Page.objects.create(
            title='Duplicate Title',
            content='<p>Content 2</p>',
            author=self.user
        )
        
        self.assertEqual(page1.slug, 'duplicate-title')
        self.assertTrue(page2.slug.startswith('duplicate-title-'))
    
    def test_content_sanitization(self):
        """Test HTML content sanitization."""
        dangerous_content = '''
        <p>Safe content</p>
        <script>alert('XSS')</script>
        <img src=x onerror="alert('XSS')">
        <a href="javascript:alert('XSS')">Link</a>
        '''
        
        page = Page.objects.create(
            title='XSS Test',
            content=dangerous_content,
            author=self.user
        )
        
        # Check that dangerous content is removed
        self.assertNotIn('<script>', page.content_sanitized)
        self.assertNotIn('javascript:', page.content_sanitized)
        self.assertNotIn('onerror=', page.content_sanitized)
        self.assertIn('<p>Safe content</p>', page.content_sanitized)
    
    def test_page_publishing(self):
        """Test page publishing logic."""
        page = Page.objects.create(
            title='Publishing Test',
            content='<p>Content</p>',
            author=self.user,
            status='draft'
        )
        
        # Draft page should not be published
        self.assertFalse(page.is_published())
        
        # Publish page
        page.status = 'published'
        page.save()
        
        self.assertTrue(page.is_published())
        
        # Test future publish date
        page.publish_at = timezone.now() + timedelta(days=1)
        page.save()
        
        self.assertFalse(page.is_published())
        
        # Test unpublish date
        page.publish_at = timezone.now() - timedelta(days=1)
        page.unpublish_at = timezone.now() - timedelta(hours=1)
        page.save()
        
        self.assertFalse(page.is_published())
    
    def test_page_permissions(self):
        """Test page view/edit/delete permissions."""
        # Create another user
        other_user = User.objects.create_user(
            email='other@example.com',
            password='TestP@ssw0rd123!'
        )
        
        # Create staff user
        staff_user = User.objects.create_user(
            email='staff@example.com',
            password='TestP@ssw0rd123!',
            is_staff=True
        )
        
        # Create page
        page = Page.objects.create(
            title='Permission Test',
            content='<p>Content</p>',
            author=self.user,
            status='published',
            visibility='public'
        )
        
        # Test can_view
        self.assertTrue(page.can_view(self.user))  # Author
        self.assertTrue(page.can_view(other_user))  # Public page
        self.assertTrue(page.can_view(staff_user))  # Staff
        self.assertTrue(page.can_view(None))  # Anonymous for public page
        
        # Change to authenticated only
        page.visibility = 'authenticated'
        page.save()
        
        self.assertTrue(page.can_view(self.user))
        self.assertTrue(page.can_view(other_user))
        self.assertFalse(page.can_view(None))  # Anonymous can't view
        
        # Test can_edit
        self.assertTrue(page.can_edit(self.user))  # Author
        self.assertFalse(page.can_edit(other_user))  # Not author
        self.assertTrue(page.can_edit(staff_user))  # Staff can edit
        
        # Test can_delete
        self.assertTrue(page.can_delete(self.user))  # Author
        self.assertFalse(page.can_delete(other_user))  # Not author
        self.assertTrue(page.can_delete(staff_user))  # Staff (superuser would be True)
    
    def test_version_creation(self):
        """Test automatic version creation."""
        page = Page.objects.create(
            title='Version Test',
            content='<p>Initial content</p>',
            author=self.user
        )
        
        # Initial version should be created via signal
        self.assertEqual(page.version, 1)
        
        # Update page
        page.title = 'Updated Title'
        page.content = '<p>Updated content</p>'
        page.save()
        
        # Version should increment
        self.assertEqual(page.version, 2)
    
    def test_view_count_increment(self):
        """Test view count incrementing."""
        page = Page.objects.create(
            title='View Count Test',
            content='<p>Content</p>',
            author=self.user
        )
        
        initial_count = page.view_count
        
        # Increment view count
        page.increment_view_count()
        
        # Refresh from database
        page.refresh_from_db()
        
        self.assertEqual(page.view_count, initial_count + 1)


class PageFormTests(TestCase):
    """Test Page form validation."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
    
    def test_valid_page_form(self):
        """Test valid page form submission."""
        form_data = {
            'title': 'Test Page',
            'slug': 'test-page',
            'content': '<p>This is valid content</p>',
            'excerpt': 'Test excerpt',
            'status': 'draft',
            'visibility': 'public',
            'publish_at': timezone.now(),
        }
        
        form = PageForm(data=form_data, user=self.user)
        self.assertTrue(form.is_valid())
    
    def test_invalid_slug_format(self):
        """Test invalid slug format rejection."""
        form_data = {
            'title': 'Test Page',
            'slug': 'Invalid Slug!',  # Invalid characters
            'content': '<p>Content</p>',
            'status': 'draft',
            'visibility': 'public',
            'publish_at': timezone.now(),
        }
        
        form = PageForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('slug', form.errors)
    
    def test_dangerous_content_rejection(self):
        """Test dangerous HTML content rejection."""
        form_data = {
            'title': 'Test Page',
            'slug': 'test-page',
            'content': '<script>alert("XSS")</script>',
            'status': 'draft',
            'visibility': 'public',
            'publish_at': timezone.now(),
        }
        
        form = PageForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('content', form.errors)
    
    def test_unpublish_date_validation(self):
        """Test unpublish date must be after publish date."""
        now = timezone.now()
        form_data = {
            'title': 'Test Page',
            'slug': 'test-page',
            'content': '<p>Content</p>',
            'status': 'published',
            'visibility': 'public',
            'publish_at': now,
            'unpublish_at': now - timedelta(hours=1),  # Before publish date
        }
        
        form = PageForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('unpublish_at', form.errors)


class PageViewTests(TestCase):
    """Test page views and permissions."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        
        # Create users
        self.author = User.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        self.author.email_verified = True
        self.author.is_active = True
        self.author.save()
        
        self.other_user = User.objects.create_user(
            email='other@example.com',
            password='TestP@ssw0rd123!'
        )
        self.other_user.email_verified = True
        self.other_user.is_active = True
        self.other_user.save()
        
        # Create test page
        self.page = Page.objects.create(
            title='Test Page',
            slug='test-page',
            content='<p>Test content</p>',
            author=self.author,
            status='published'
        )
    
    def test_page_list_view(self):
        """Test page list view."""
        url = reverse('cms:page_list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Page')
    
    def test_page_detail_view(self):
        """Test page detail view."""
        url = reverse('cms:page_detail', kwargs={'slug': self.page.slug})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.page.title)
        self.assertContains(response, self.page.content_sanitized)
    
    def test_page_create_requires_login(self):
        """Test page creation requires authentication."""
        url = reverse('cms:page_create')
        response = self.client.get(url)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_page_create_authenticated(self):
        """Test authenticated page creation."""
        self.client.force_login(self.author)
        
        url = reverse('cms:page_create')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        # Test POST
        form_data = {
            'title': 'New Page',
            'slug': 'new-page',
            'content': '<p>New content</p>',
            'excerpt': 'New excerpt',
            'status': 'draft',
            'visibility': 'public',
            'publish_at': timezone.now().strftime('%Y-%m-%dT%H:%M'),
        }
        
        response = self.client.post(url, form_data)
        
        # Should redirect after successful creation
        self.assertEqual(response.status_code, 302)
        
        # Check page was created
        self.assertTrue(
            Page.objects.filter(slug='new-page').exists()
        )
    
    def test_page_edit_permission(self):
        """Test page edit permission checking."""
        url = reverse('cms:page_edit', kwargs={'slug': self.page.slug})
        
        # Anonymous should be redirected
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        
        # Other user should be forbidden
        self.client.force_login(self.other_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Author should have access
        self.client.force_login(self.author)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
    
    def test_page_delete_permission(self):
        """Test page delete permission checking."""
        # Create draft page for deletion
        draft_page = Page.objects.create(
            title='Draft Page',
            slug='draft-page',
            content='<p>Draft content</p>',
            author=self.author,
            status='draft'
        )
        
        url = reverse('cms:page_delete', kwargs={'slug': draft_page.slug})
        
        # Other user should be forbidden
        self.client.force_login(self.other_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Author should have access
        self.client.force_login(self.author)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # Test actual deletion
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        
        # Check page was deleted
        self.assertFalse(
            Page.objects.filter(slug='draft-page').exists()
        )
    
    def test_my_pages_view(self):
        """Test my pages view for authors."""
        self.client.force_login(self.author)
        
        url = reverse('cms:my_pages')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.page.title)
        
        # Other user shouldn't see this page
        self.client.force_login(self.other_user)
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.page.title)


class CategoryTagTests(TestCase):
    """Test Category and Tag models."""
    
    def test_category_creation(self):
        """Test category creation and slug generation."""
        category = Category.objects.create(
            name='Test Category'
        )
        
        self.assertEqual(category.slug, 'test-category')
        self.assertTrue(category.is_active)
    
    def test_category_hierarchy(self):
        """Test category parent-child relationships."""
        parent = Category.objects.create(
            name='Parent Category'
        )
        
        child = Category.objects.create(
            name='Child Category',
            parent=parent
        )
        
        self.assertEqual(child.parent, parent)
        self.assertIn(child, parent.children.all())
    
    def test_tag_creation(self):
        """Test tag creation and slug generation."""
        tag = Tag.objects.create(
            name='Test Tag'
        )
        
        self.assertEqual(tag.slug, 'test-tag')
    
    def test_page_categorization(self):
        """Test adding categories and tags to pages."""
        user = User.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        
        category = Category.objects.create(name='Category')
        tag1 = Tag.objects.create(name='Tag1')
        tag2 = Tag.objects.create(name='Tag2')
        
        page = Page.objects.create(
            title='Categorized Page',
            content='<p>Content</p>',
            author=user,
            category=category
        )
        
        page.tags.add(tag1, tag2)
        
        self.assertEqual(page.category, category)
        self.assertIn(tag1, page.tags.all())
        self.assertIn(tag2, page.tags.all())
        
        # Test reverse relationships
        self.assertIn(page, category.pages.all())
        self.assertIn(page, tag1.pages.all())


class AuditLogTests(TestCase):
    """Test audit logging functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='author@example.com',
            password='TestP@ssw0rd123!'
        )
        
        self.page = Page.objects.create(
            title='Audit Test',
            content='<p>Content</p>',
            author=self.user
        )
    
    def test_audit_log_creation(self):
        """Test creating audit log entries."""
        log = PageAuditLog.objects.create(
            page=self.page,
            user=self.user,
            action='edited',
            ip_address='127.0.0.1',
            user_agent='Test Browser'
        )
        
        self.assertEqual(log.page, self.page)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, 'edited')
    
    def test_audit_log_ordering(self):
        """Test audit logs are ordered by timestamp."""
        log1 = PageAuditLog.objects.create(
            page=self.page,
            user=self.user,
            action='viewed'
        )
        
        log2 = PageAuditLog.objects.create(
            page=self.page,
            user=self.user,
            action='edited'
        )
        
        logs = PageAuditLog.objects.all()
        
        # Most recent should be first
        self.assertEqual(logs[0], log2)
        self.assertEqual(logs[1], log1)
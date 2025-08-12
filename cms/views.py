"""
Views for CMS page management with RBAC and security.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, F
from django.http import HttpResponseForbidden, JsonResponse, Http404
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.generic import (
    ListView, DetailView, CreateView, UpdateView, DeleteView
)
from django.views.decorators.cache import cache_page, never_cache
from django.views.decorators.csrf import csrf_protect
from django_ratelimit.decorators import ratelimit

from .models import Page, PageVersion, PageAuditLog, Category, Tag
from .forms import PageForm, PageSearchForm, CategoryForm, TagForm, BulkActionForm


class PageListView(ListView):
    """
    List view for pages with filtering and search.
    """
    model = Page
    template_name = 'cms/page_list.html'
    context_object_name = 'pages'
    paginate_by = 20
    
    def get_queryset(self):
        """Filter pages based on user permissions and search."""
        # Base queryset filtered by user permissions
        queryset = Page.objects.visible_to_user(self.request.user)
        
        # Search and filter
        form = PageSearchForm(self.request.GET)
        if form.is_valid():
            # Text search
            q = form.cleaned_data.get('q')
            if q:
                queryset = queryset.filter(
                    Q(title__icontains=q) |
                    Q(content__icontains=q) |
                    Q(excerpt__icontains=q)
                )
            
            # Category filter
            category = form.cleaned_data.get('category')
            if category:
                queryset = queryset.filter(category=category)
            
            # Status filter
            status = form.cleaned_data.get('status')
            if status:
                queryset = queryset.filter(status=status)
            
            # Author filter
            author = form.cleaned_data.get('author')
            if author:
                queryset = queryset.filter(
                    Q(author__email__icontains=author) |
                    Q(author__first_name__icontains=author) |
                    Q(author__last_name__icontains=author)
                )
            
            # Date range filter
            date_from = form.cleaned_data.get('date_from')
            if date_from:
                queryset = queryset.filter(created_at__date__gte=date_from)
            
            date_to = form.cleaned_data.get('date_to')
            if date_to:
                queryset = queryset.filter(created_at__date__lte=date_to)
            
            # Featured filter
            if form.cleaned_data.get('featured'):
                queryset = queryset.filter(featured=True)
        
        # Ordering
        order = self.request.GET.get('order', '-publish_at')
        if order in ['title', '-title', 'publish_at', '-publish_at', 
                     'view_count', '-view_count', 'created_at', '-created_at']:
            queryset = queryset.order_by(order)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_form'] = PageSearchForm(self.request.GET)
        context['total_count'] = self.get_queryset().count()
        
        # Stats for authenticated users
        if self.request.user.is_authenticated:
            context['my_pages_count'] = Page.objects.filter(
                author=self.request.user
            ).count()
            context['draft_count'] = Page.objects.filter(
                author=self.request.user,
                status='draft'
            ).count()
        
        return context


class PageDetailView(DetailView):
    """
    Detail view for a single page with permissions check.
    """
    model = Page
    template_name = 'cms/page_detail.html'
    context_object_name = 'page'
    slug_field = 'slug'
    slug_url_kwarg = 'slug'
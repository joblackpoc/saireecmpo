"""
Custom permission classes for API endpoints.
"""

from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            # Check if object has can_view method
            if hasattr(obj, 'can_view'):
                return obj.can_view(request.user)
            return True
        
        # Write permissions are only allowed to the owner
        if hasattr(obj, 'author'):
            return obj.author == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        
        return False


class IsStaffOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow staff to edit.
    """
    
    def has_permission(self, request, view):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to staff
        return request.user and request.user.is_staff


class IsOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object.
    """
    
    def has_object_permission(self, request, view, obj):
        # Check ownership
        if hasattr(obj, 'author'):
            return obj.author == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        
        return False


class CanEditPage(permissions.BasePermission):
    """
    Custom permission for page editing.
    """
    
    def has_object_permission(self, request, view, obj):
        # Use page's can_edit method
        if hasattr(obj, 'can_edit'):
            return obj.can_edit(request.user)
        
        return False


class CanDeletePage(permissions.BasePermission):
    """
    Custom permission for page deletion.
    """
    
    def has_object_permission(self, request, view, obj):
        # Use page's can_delete method
        if hasattr(obj, 'can_delete'):
            return obj.can_delete(request.user)
        
        return False


class IsEmailVerified(permissions.BasePermission):
    """
    Permission to check if user's email is verified.
    """
    
    message = 'Email verification required.'
    
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            return request.user.email_verified
        return False


class IsNotLocked(permissions.BasePermission):
    """
    Permission to check if user account is not locked.
    """
    
    message = 'Account is locked due to security reasons.'
    
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            if hasattr(request.user, 'is_account_locked'):
                return not request.user.is_account_locked()
            return not request.user.is_locked
        return True
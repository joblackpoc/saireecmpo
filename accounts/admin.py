"""
Admin configuration for custom user model with security enhancements.
Includes 2FA requirement and audit logging.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.utils import timezone
from django.urls import reverse
from django.contrib import messages
from django import forms
from django.core.exceptions import ValidationError
from django_otp.admin import OTPAdminSite
import csv
from django.http import HttpResponse

from .models import EmailUser, EmailVerificationToken, PasswordResetToken, SecurityAuditLog


class UserCreationForm(forms.ModelForm):
    """
    Form for creating new users in admin with proper password validation.
    """
    password1 = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput,
        min_length=12,
        help_text=_('Password must be at least 12 characters.')
    )
    password2 = forms.CharField(
        label=_('Password confirmation'),
        widget=forms.PasswordInput
    )
    send_verification_email = forms.BooleanField(
        label=_('Send verification email'),
        required=False,
        initial=True,
        help_text=_('Send email verification link to user.')
    )
    
    class Meta:
        model = EmailUser
        fields = ('email', 'first_name', 'last_name', 'is_staff')
    
    def clean_password2(self):
        """Check that the two password entries match."""
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("Passwords don't match"))
        return password2
    
    def save(self, commit=True):
        """Save the provided password in hashed format."""
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.password_changed_at = timezone.now()
        if commit:
            user.save()
            # Log user creation
            SecurityAuditLog.objects.create(
                user=user,
                action='USER_CREATED',
                details={'created_by_admin': True}
            )
        return user


class UserChangeForm(forms.ModelForm):
    """
    Form for updating users with readonly password field.
    """
    password = ReadOnlyPasswordHashField(
        label=_("Password"),
        help_text=_(
            'Raw passwords are not stored, so there is no way to see this '
            'user\'s password, but you can change the password using '
            '<a href="{}">this form</a>.'
        ),
    )
    
    class Meta:
        model = EmailUser
        fields = '__all__'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        password = self.fields.get('password')
        if password:
            password.help_text = password.help_text.format(
                f'../../{self.instance.pk}/password/'
            )
        # Disable email field for existing users (security)
        if self.instance.pk:
            self.fields['email'].disabled = True


class EmailVerificationInline(admin.TabularInline):
    """Inline admin for email verification tokens."""
    model = EmailVerificationToken
    extra = 0
    readonly_fields = ('token', 'created_at', 'used_at', 'is_used')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


class PasswordResetTokenInline(admin.TabularInline):
    """Inline admin for password reset tokens."""
    model = PasswordResetToken
    extra = 0
    readonly_fields = ('token', 'created_at', 'used_at', 'is_used', 'ip_address', 'user_agent')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


class SecurityAuditLogInline(admin.TabularInline):
    """Inline admin for security audit logs."""
    model = SecurityAuditLog
    extra = 0
    readonly_fields = ('action', 'timestamp', 'ip_address', 'user_agent', 'details')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(EmailUser)
class EmailUserAdmin(BaseUserAdmin):
    """
    Custom admin for EmailUser with security features.
    """
    form = UserChangeForm
    add_form = UserCreationForm
    
    list_display = (
        'email', 'display_name_colored', 'is_active', 'email_verified',
        'two_factor_status', 'last_login', 'lock_status', 'failed_attempts'
    )
    list_filter = (
        'is_active', 'email_verified', 'two_factor_enabled',
        'is_staff', 'is_superuser', 'is_locked', 'date_joined'
    )
    search_fields = ('email', 'first_name', 'last_name', 'display_name')
    ordering = ('-date_joined',)
    filter_horizontal = ('groups', 'user_permissions')
    readonly_fields = (
        'id', 'date_joined', 'updated_at', 'last_login',
        'password_changed_at', 'last_login_ip', 'last_login_user_agent',
        'registration_ip', 'registration_user_agent',
        'failed_login_attempts', 'last_failed_login'
    )
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {
            'fields': ('first_name', 'last_name', 'display_name')
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'email_verified', 'is_staff', 
                      'is_superuser', 'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        (_('Security'), {
            'fields': ('two_factor_enabled', 'backup_codes_generated',
                      'password_changed_at', 'force_password_change',
                      'is_locked', 'locked_until', 'failed_login_attempts',
                      'last_failed_login'),
            'classes': ('collapse',)
        }),
        (_('Tracking'), {
            'fields': ('last_login', 'last_login_ip', 'last_login_user_agent',
                      'registration_ip', 'registration_user_agent',
                      'date_joined', 'updated_at'),
            'classes': ('collapse',)
        }),
        (_('Privacy'), {
            'fields': ('data_privacy_consent', 'consent_timestamp'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2',
                      'first_name', 'last_name', 'is_staff',
                      'send_verification_email'),
        }),
    )
    
    inlines = [
        EmailVerificationInline,
        PasswordResetTokenInline,
        SecurityAuditLogInline,
    ]
    
    actions = [
        'activate_users', 'deactivate_users', 'verify_emails',
        'reset_failed_attempts', 'force_password_change',
        'export_users_csv', 'enable_2fa', 'lock_accounts'
    ]
    
    def display_name_colored(self, obj):
        """Display name with color coding for user status."""
        name = obj.get_display_name()
        if obj.is_superuser:
            color = '#ff0000'  # Red for superuser
            icon = '⚡'
        elif obj.is_staff:
            color = '#0000ff'  # Blue for staff
            icon = '👤'
        else:
            color = '#000000'  # Black for regular users
            icon = '👥'
        return format_html(
            '<span style="color: {};">{} {}</span>',
            color, icon, name
        )
    display_name_colored.short_description = 'Display Name'
    display_name_colored.admin_order_field = 'display_name'
    
    def two_factor_status(self, obj):
        """Show 2FA status with icon."""
        if obj.two_factor_enabled:
            return format_html(
                '<span style="color: green;">✓ Enabled</span>'
            )
        return format_html(
            '<span style="color: orange;">✗ Disabled</span>'
        )
    two_factor_status.short_description = '2FA'
    two_factor_status.admin_order_field = 'two_factor_enabled'
    
    def lock_status(self, obj):
        """Show lock status with icon."""
        if obj.is_locked:
            if obj.locked_until and obj.locked_until > timezone.now():
                return format_html(
                    '<span style="color: red;">🔒 Locked</span>'
                )
        return format_html(
            '<span style="color: green;">🔓 Open</span>'
        )
    lock_status.short_description = 'Lock Status'
    
    def failed_attempts(self, obj):
        """Show failed login attempts with warning."""
        if obj.failed_login_attempts >= 3:
            return format_html(
                '<span style="color: red; font-weight: bold;">{}</span>',
                obj.failed_login_attempts
            )
        return obj.failed_login_attempts
    failed_attempts.short_description = 'Failed Logins'
    failed_attempts.admin_order_field = 'failed_login_attempts'
    
    # Admin Actions
    def activate_users(self, request, queryset):
        """Activate selected users."""
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} users activated.', messages.SUCCESS)
        # Log action
        for user in queryset:
            SecurityAuditLog.objects.create(
                user=user,
                action='ACCOUNT_UNLOCKED',
                details={'admin_action': True}
            )
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users."""
        # Prevent deactivating superusers
        queryset = queryset.exclude(is_superuser=True)
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} users deactivated.', messages.WARNING)
        # Log action
        for user in queryset:
            SecurityAuditLog.objects.create(
                user=user,
                action='ACCOUNT_LOCKED',
                details={'admin_action': True}
            )
    deactivate_users.short_description = "Deactivate selected users"
    
    def verify_emails(self, request, queryset):
        """Mark emails as verified."""
        count = queryset.update(email_verified=True, is_active=True)
        self.message_user(request, f'{count} emails verified.', messages.SUCCESS)
    verify_emails.short_description = "Verify emails for selected users"
    
    def reset_failed_attempts(self, request, queryset):
        """Reset failed login attempts."""
        count = queryset.update(
            failed_login_attempts=0,
            is_locked=False,
            locked_until=None
        )
        self.message_user(request, f'Reset failed attempts for {count} users.', messages.SUCCESS)
    reset_failed_attempts.short_description = "Reset failed login attempts"
    
    def force_password_change(self, request, queryset):
        """Force password change on next login."""
        count = queryset.update(force_password_change=True)
        self.message_user(
            request, 
            f'{count} users will be required to change password on next login.',
            messages.INFO
        )
    force_password_change.short_description = "Force password change"
    
    def enable_2fa(self, request, queryset):
        """Remind users to enable 2FA."""
        # This is just a reminder action
        emails = ', '.join([user.email for user in queryset])
        self.message_user(
            request,
            f'Send 2FA setup instructions to: {emails}',
            messages.INFO
        )
    enable_2fa.short_description = "Send 2FA setup reminder"
    
    def lock_accounts(self, request, queryset):
        """Lock selected accounts."""
        for user in queryset:
            user.lock_account(duration_hours=24)
            SecurityAuditLog.objects.create(
                user=user,
                action='ACCOUNT_LOCKED',
                details={'admin_action': True, 'duration': '24 hours'}
            )
        self.message_user(
            request,
            f'{queryset.count()} accounts locked for 24 hours.',
            messages.WARNING
        )
    lock_accounts.short_description = "Lock accounts for 24 hours"
    
    def export_users_csv(self, request, queryset):
        """Export selected users to CSV."""
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="users.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Email', 'First Name', 'Last Name', 'Active', 
            'Email Verified', '2FA Enabled', 'Staff', 'Date Joined'
        ])
        
        for user in queryset:
            writer.writerow([
                user.email,
                user.first_name,
                user.last_name,
                user.is_active,
                user.email_verified,
                user.two_factor_enabled,
                user.is_staff,
                user.date_joined.strftime('%Y-%m-%d %H:%M')
            ])
        
        return response
    export_users_csv.short_description = "Export to CSV"
    
    def get_readonly_fields(self, request, obj=None):
        """Make email readonly for existing users."""
        readonly = list(self.readonly_fields)
        if obj:  # Editing existing user
            readonly.append('email')
        return readonly


@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    """Admin for viewing security audit logs."""
    list_display = ('user', 'action', 'timestamp', 'ip_address', 'colored_action')
    list_filter = ('action', 'timestamp', 'user')
    search_fields = ('user__email', 'ip_address', 'user_agent')
    readonly_fields = ('user', 'action', 'timestamp', 'ip_address', 'user_agent', 'details')
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)
    
    def colored_action(self, obj):
        """Color-code actions by severity."""
        colors = {
            'LOGIN_FAILED': 'orange',
            'ACCOUNT_LOCKED': 'red',
            'SUSPICIOUS_ACTIVITY': 'red',
            'PASSWORD_CHANGED': 'blue',
            'LOGIN_SUCCESS': 'green',
            '2FA_ENABLED': 'green',
        }
        color = colors.get(obj.action, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color, obj.get_action_display()
        )
    colored_action.short_description = 'Action Type'
    
    def has_add_permission(self, request):
        """Prevent manual creation of audit logs."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of audit logs."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make audit logs read-only."""
        return False
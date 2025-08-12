from django.apps import AppConfig


class CmsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cms'
    verbose_name = 'CMS'
    
    def ready(self):
        # Import signal handlers
        try:
            import apps.cms.signals
        except ImportError:
            pass

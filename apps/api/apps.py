from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'
    verbose_name = 'REST API'
    
    def ready(self):
        """Import any necessary modules when app is ready."""
        pass

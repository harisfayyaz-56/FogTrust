from django.apps import AppConfig


class HeartbeatsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "heartbeats"
    verbose_name = "Signed heartbeats and replay defence"
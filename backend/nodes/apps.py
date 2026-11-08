from django.apps import AppConfig


class NodesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "nodes"
    verbose_name = "Nodes and enrollment"

    def ready(self):
        from . import checks  # noqa: F401  (registers the server-key system check)

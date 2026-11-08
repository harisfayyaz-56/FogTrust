from django.contrib import admin

from .models import AuditEvent


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    """Read-only developer view. The database triggers would block edits anyway."""

    list_display = ("sequence", "timestamp", "actor_id", "action", "outcome", "reason_code")
    list_filter = ("outcome", "actor_type", "action")
    search_fields = ("action", "actor_id", "target_id", "reason_code", "request_id")
    ordering = ("-sequence",)

    def get_readonly_fields(self, request, obj=None):
        return [field.name for field in self.model._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

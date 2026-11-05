from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "role", "is_active", "last_login")
    list_filter = ("role", "is_active")
    fieldsets = DjangoUserAdmin.fieldsets + (("FogTrust", {"fields": ("role",)}),)
    add_fieldsets = DjangoUserAdmin.add_fieldsets + (("FogTrust", {"fields": ("role",)}),)

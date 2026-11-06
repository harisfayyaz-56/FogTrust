from django.urls import path

from . import views

app_name = "audit"

urlpatterns = [
    path("", views.AuditEventListView.as_view(), name="list"),
    path("verify/", views.AuditVerifyView.as_view(), name="verify"),
]

from django.urls import path

from . import user_views

app_name = "users"

urlpatterns = [
    path("", user_views.UserListCreateView.as_view(), name="list"),
    path("<str:user_id>/", user_views.UserDetailView.as_view(), name="detail"),
]

from django.urls import path
from tasks import views

app_name = "tasks"

urlpatterns = [
    path("", views.TaskSubmitView.as_view(), name="submit"),
    path("list/", views.TaskListView.as_view(), name="list"),
    path("<uuid:id>/", views.TaskDetailView.as_view(), name="detail"),
    path("<uuid:id>/cancel/", views.TaskCancelView.as_view(), name="cancel"),
]


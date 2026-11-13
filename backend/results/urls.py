from django.urls import path

from . import views

app_name = "results"

urlpatterns = [
    path("node-api/tasks/<str:task_id>/result/", views.NodeResultView.as_view(), name="node-result"),
    path("tasks/<str:task_id>/result/", views.ResultDetailView.as_view(), name="result-detail"),
]
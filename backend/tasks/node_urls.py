from django.urls import path
from tasks import views

app_name = "tasks_node"

urlpatterns = [
    path("next/", views.NodeNextTaskView.as_view(), name="next"),
]

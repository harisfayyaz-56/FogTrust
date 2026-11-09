from django.urls import path

from . import views

app_name = "heartbeats"

urlpatterns = [
    path("node-api/heartbeat/", views.NodeHeartbeatView.as_view(), name="heartbeat"),
    path("nodes/<str:node_id>/heartbeats/", views.NodeHeartbeatListView.as_view(), name="node-heartbeats"),
]
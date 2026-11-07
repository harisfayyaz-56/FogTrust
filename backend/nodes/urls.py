from django.urls import path

from . import views

app_name = "nodes"

urlpatterns = [
    path("enrollment-tokens/", views.EnrollmentTokenListCreateView.as_view(), name="token-list"),
    path("enrollment-tokens/<str:token_id>/cancel/", views.EnrollmentTokenCancelView.as_view(), name="token-cancel"),
    path("nodes/enroll/", views.NodeEnrollView.as_view(), name="enroll"),
    path("nodes/", views.NodeListView.as_view(), name="node-list"),
    path("nodes/<str:node_id>/", views.NodeDetailView.as_view(), name="node-detail"),
    path("nodes/<str:node_id>/revoke/", views.NodeRevokeView.as_view(), name="node-revoke"),
]

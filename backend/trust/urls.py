from django.urls import path
from trust import views

app_name = "trust"

urlpatterns = [
    path("nodes/<uuid:node_id>/trust/", views.NodeTrustHistoryView.as_view(), name="node_trust_history"),
    path("policy/", views.PolicyCurrentView.as_view(), name="policy_current"),
    path("policy/update/", views.PolicyUpdateView.as_view(), name="policy_update"),
]


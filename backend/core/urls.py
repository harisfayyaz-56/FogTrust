from django.urls import path

from . import decision_views, views

app_name = "core"

urlpatterns = [
    path("health/", views.health, name="health"),
    path("decisions/", decision_views.DecisionListView.as_view(), name="decisions"),
]

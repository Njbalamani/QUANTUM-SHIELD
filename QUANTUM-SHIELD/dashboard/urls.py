from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from .views import DashboardView, HealthView, LandingView

app_name = "dashboard"

urlpatterns = [
    path("", LandingView.as_view(), name="landing"),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("health/", HealthView.as_view(), name="health"),
    path(
        "login/",
        LoginView.as_view(template_name="registration/login.html", redirect_authenticated_user=True),
        name="login",
    ),
    path("logout/", LogoutView.as_view(next_page="/"), name="logout"),
]

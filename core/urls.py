from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("register/", views.registerView, name="register"),
    path("login/", views.loginView, name="login"),
    path("logout/", views.logoutView, name="logout"),
    path("forgot-password/", views.ForgotPassword, name="forgot-password"),
    path(
        "password-reset-sent/<str:reset_id>/",
        views.PasswordResetSent,
        name="password-reset-sent",
    ),
    path("reset-password/<str:reset_id>/", views.ResetPassword, name="reset-password"),
]

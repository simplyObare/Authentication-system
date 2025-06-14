from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("register/", views.registerView, name="register"),
    path("login/", views.loginView, name="login"),
]

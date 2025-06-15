from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User


def home(request):
    return render(request, "core/index.html")


def registerView(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        password = request.POST.get("password")
        repeat_password = request.POST.get("repeat_password")

        user_data_has_error = False

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "User already exists")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")

        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, "Your Password must be at least 5 characters")

        if password != repeat_password:
            user_data_has_error = True
            messages.error(request, "Passwords do not match.")

        if user_data_has_error:
            return redirect("register")

        # Create the user if no errors
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        user.save()
        messages.success(request, "Registration successful! Please log in.")
        return redirect("login")  # Change 'login' to your login URL name

    return render(request, "core/register.html")


def loginView(request):
    return render(request, "core/login.html")

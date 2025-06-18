from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from .models import PasswordReset


@login_required
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
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("home")
        else:
            messages.error(request, "Invalid credentials")
            return redirect("login")

    return render(request, "core/login.html")


def logoutView(request):
    logout(request)
    return redirect("login")


def ForgotPassword(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
            # Password reset logic
            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse(
                "reset-password", kwargs={"reset_id": new_password_reset.reset_id}
            )

            full_password_reset_url = (
                f"{request.scheme}://{request.get_host()}{password_reset_url}"
            )

            email_body = f"Reset your password using thr link below:\n\n\n{full_password_reset_url}"

            email_message = EmailMessage(
                "Reset your password",  # email subject
                email_body,
                settings.EMAIL_HOST_USER,  # email sender
                [email],  # email  receiver
            )

            email_message.send(fail_silently=True)

            messages.success(request, "Password reset instructions sent to your email.")

            return redirect("password-reset-sent", reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, "No user with that email exists.")
        return render(request, "core/forgot_password.html")
    else:
        return render(request, "core/forgot_password.html")


def PasswordResetSent(request, reset_id):
    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, "core/password_reset_sent.html", {"reset_id": reset_id})
    else:
        messages.error(request, "Invalid reset id")
        return redirect("forgot-password")


def ResetPassword(request, reset_id):
    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get("password")
            confirm_password = request.POST.get("confirm-password")

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, "Passwords do not match")

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, "Password must be at least 5 characters long")

            # check to make sure link has not expired
            expiration_time = password_reset_id.created_when + timezone.timedelta(
                minutes=10
            )
            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, "Reset link has expired")
                password_reset_id.delete()

            # reset password
            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()
                password_reset_id.delete()
                messages.success(request, "Password reset. Proceed to login")
                return redirect("login")
            else:
                # stay on the same page and display errors
                return render(
                    request, "core/reset_password.html", {"reset_id": reset_id}
                )

    except PasswordReset.DoesNotExist:
        messages.error(request, "Invalid reset id")
        return redirect("forgot-password")

    return render(request, "core/reset_password.html", {"reset_id": reset_id})

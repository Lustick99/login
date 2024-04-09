# accounts/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.views.generic import CreateView
from django.contrib import messages

from .models import UserAccount
from .forms import UserForm

class UserSignUpView(CreateView):
    model = UserAccount
    form_class = UserForm
    template_name = 'login/register.html'
    
    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect('admin:index')

    
def user_login(request):
    if request.user.is_authenticated:
        return redirect('admin:index')

    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        user = authenticate(request, email= email, password = password)

        if user is not None:
            login(request, user)
            messages.info(request, f"You are now logged in as {user}.")
            return redirect('admin:index')
        else:
            return render(request, "login/login.html", messages.error(request, "username or password is undefine!"))

    return render(request, 'login/login.html')

@login_required
def user_logout(request):
    logout(request)
    return redirect('home')  # Redirigez l'utilisateur après la déconnexion

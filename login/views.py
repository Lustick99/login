# accounts/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.views.generic import CreateView
from django.contrib import messages
import random

from .models import UserAccount
from .forms import UserForm, FormulaireDeModificationDuMotDePasse, FormulaireMotDePasseOublie


def index(request):
    user = request.user
    
    context = {
        'user' : user,
    }
    
    return render(request, 'login/index.html', context)


class UserSignUpView(CreateView):
    model = UserAccount
    form_class = UserForm
    template_name = 'login/register.html'
    
    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect('index')

    
def user_login(request):

    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        user = authenticate(request, email= email, password = password)

        if user is not None:
            login(request, user)
            if request.user.is_authenticated:
                if request.user.is_admin:
                    return redirect('admin:index')
                else:
                    return redirect('index')
            messages.info(request, f"You are now logged in as {user}.")
            return redirect('index')
        else:
            return render(request, "login/login.html", messages.error(request, "username or password is undefine!"))

    return render(request, 'login/login.html')


@login_required
def user_logout(request):
    logout(request)
    return redirect('index')  # Redirigez l'utilisateur après la déconnexion


@login_required
def modifier_vos_informations(request):
    user = UserAccount.objects.get(id=request.user.id)
    if request.method == 'POST':
        form = UserForm(request.POST, instance=user)
        if form.is_valid():
            if check_password(form.cleaned_data['password1'], user.password) == True:
                user.last_name = form.cleaned_data['last_name']
                user.first_name = form.cleaned_data['first_name']
                user.email = form.cleaned_data['email']
                user.contact = form.cleaned_data['contact']

                user.save()
                logout(request)
                return redirect('log:login')
            else:
                return redirect('log:modifinfos')
    else:
        form = UserForm(instance=user)
        
    context = {
       'form' : form,
       'user' : user,
    }
    return render(request, 'login/modifier-vos-informations.html', context)


@login_required
def modifier_votre_mot_de_passe(request):
    if request.method == 'POST':
        form = FormulaireDeModificationDuMotDePasse(request.POST)
        if form.is_valid():
            if check_password(form.cleaned_data['mot_de_passe'], request.user.password):
                if form.cleaned_data['nouveau_mot_de_passe'] == form.cleaned_data['confirmation_du_nouveau_mot_de_passe']:
                    request.user.set_password(form.cleaned_data['nouveau_mot_de_passe'])
                    request.user.save()
                    return redirect('log:logout')
                else:
                  return redirect('modifier-votre-mot-de-passe')  
            else:
                return redirect('modifier-votre-mot-de-passe')
        else:
            return redirect('modifier-votre-mot-de-passe')
    else:
        form = FormulaireDeModificationDuMotDePasse()
    return render(request, 'login/modifier-votre-mot-de-passe.html', {'form': FormulaireDeModificationDuMotDePasse()})


def mot_de_passe_oublie(request):
    if request.method == 'POST':
        form = FormulaireMotDePasseOublie(request.POST)
        if form.is_valid():
            caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\/|!@#$%?&*()_+ÀÇ¨È:É\"'{}[]-=àç^è;é.,"
            mot_de_passe = ""
            for c in range(16):
                mot_de_passe += random.choice(caracteres)
            
            user = UserAccount.objects.get(email=form.cleaned_data['email'])
            if user is None:
                user.set_password(mot_de_passe)
                user.save()
                logout(request)
                print(mot_de_passe)
                send_mail('Réinitialisation de votre mot de passe.', 'Votre nouveau mot de passe est '+mot_de_passe+' veuillez le changer une fois connecté.', 'pierreclaverulr@gmail.com', [form.cleaned_data['email']], fail_silently=False,)
                return redirect('log:login')
            else:
                print('Aucun compte enrégistré avec ce email')
                form = FormulaireMotDePasseOublie()
                return redirect('log:passe_oublie')
                
    else:
        form = FormulaireMotDePasseOublie()
    return render(request, 'login/mot-de-passe-oublie.html', {'form': FormulaireMotDePasseOublie()})


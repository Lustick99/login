# accounts/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import UserAccount

from phonenumber_field.formfields import PhoneNumberField
from phonenumber_field.widgets import PhoneNumberPrefixWidget


class UserForm(UserCreationForm):

	contact = PhoneNumberField(required=True, label="Numero de Telephone", widget=PhoneNumberPrefixWidget())

	class Meta:
		model = UserAccount
		fields = ['email', 'first_name', 'last_name', 'contact'] 

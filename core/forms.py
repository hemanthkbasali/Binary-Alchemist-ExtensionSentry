from __future__ import annotations

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class StyledFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            existing = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{existing} cyber-input".strip()


class SignupForm(StyledFormMixin, UserCreationForm):
    organization_name = forms.CharField(max_length=160)
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ("email", "organization_name", "password1", "password2")

    def clean_email(self) -> str:
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(username=email).exists() or User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def save(self, commit: bool = True) -> User:
        user = super().save(commit=False)
        user.username = self.cleaned_data["email"]
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class ExtensionZipUploadForm(StyledFormMixin, forms.Form):
    archive = forms.FileField(
        label="Chrome extension ZIP or CRX-as-ZIP",
        widget=forms.ClearableFileInput(
            attrs={
                "accept": ".zip,.crx,application/zip,application/x-zip-compressed",
                "data-drop-zone-input": "true",
            }
        ),
    )
    analyst_note = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "placeholder": "Optional analyst note, case ID, or acquisition context",
            }
        ),
    )

    def clean_archive(self):
        archive = self.cleaned_data["archive"]
        name = archive.name.lower()
        if not (name.endswith(".zip") or name.endswith(".crx")):
            raise forms.ValidationError("Upload a .zip or CRX package with a ZIP-compatible body.")
        return archive

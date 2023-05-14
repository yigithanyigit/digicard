from django.core import validators
from django.db import models


from django.forms.fields import URLField as FormURLField


class CustomURLForm(FormURLField):
    default_validators = [validators.URLValidator(schemes=["http", "https", "ftp", "ftps", "mailto", "tel"])]


class CustomURLField(models.CharField):
    default_validators = [validators.URLValidator(schemes=["http", "https", "ftp", "ftps", "mailto", "tel", "bank"])]
    description = ("URL")

    def __init__(self, verbose_name=None, name=None, **kwargs):
        kwargs.setdefault("max_length", 200)
        super().__init__(verbose_name, name, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if kwargs.get("max_length") == 200:
            del kwargs["max_length"]
        return name, path, args, kwargs

    def formfield(self, **kwargs):
        # As with CharField, this will cause URL validation to be performed
        # twice.
        return super().formfield(
            **{
                "form_class": CustomURLForm,
                **kwargs,
            }
        )

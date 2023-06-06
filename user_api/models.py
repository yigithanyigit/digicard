from django.db import models
from user_api.customModels import CustomURLField
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.dispatch import receiver
from django.db.models.signals import post_delete, pre_save
from django.core import validators


class AppUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, name=None, surname=None, title=None):
        if not username:
            raise ValueError('A username is required.')
        if not email:
            raise ValueError('An email is required.')
        if not password:
            raise ValueError('A password is required.')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, name=name, surname=surname, title=title)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None, name=None, surname=None, title=None):
        if not username:
            raise ValueError('A username is required.')
        if not email:
            raise ValueError('An email is required.')
        if not password:
            raise ValueError('A password is required.')
        user = self.create_user(username, email, password, name, surname, title)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class AppUser(AbstractBaseUser, PermissionsMixin):
    user_id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=100, unique=True)
    username = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100, blank=True, null=True)
    surname = models.CharField(max_length=100, blank=True, null=True)
    title = models.CharField(max_length=100, blank=True, null=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateField(auto_now_add=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    objects = AppUserManager()

    def __str__(self):
        return self.username


class CustomUri(models.Model):
    choice_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    uri = models.CharField(max_length=50)

    class Meta:
        verbose_name = "CustomUri"
        verbose_name_plural = "CustomUris"

    def __str__(self):
        return f"{self.name} / ({self.uri})"


class Profile(models.Model):
    content_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(AppUser, on_delete=models.CASCADE)

    class FieldType(models.TextChoices):
        TELEPHONE = "Telephone"
        MAIL = "Mail"
        LOCATION = "Pin"

    type = models.CharField(
        max_length=50,
        choices=FieldType.choices,
    )

    content = models.CharField(max_length=100)
    url = models.CharField(max_length=100, blank=True, null=True)
    uri = models.ForeignKey(CustomUri, on_delete=models.CASCADE, blank=True, null=True)


class Social(models.Model):
    social_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(AppUser, on_delete=models.CASCADE)

    class SocialChoices(models.TextChoices):
        #BANK = "Bank"
        BEHANCE = "Behance"
        FACEBOOK = "Facebook"
        INSTAGRAM = "Instagram"
        LINKEDIN = "Linkedin"
        SNAPCHAT = "Snapchat"
        TWITTER = "Twitter"
        TINDER = "Tinder"
        TIKTOK = "Tiktok"
        BLOG = "Blog"

    type = models.CharField(
        max_length=50,
        choices=SocialChoices.choices,
    )

    url = models.CharField(max_length=100, blank=True, null=True)
    uri = models.ForeignKey(CustomUri, on_delete=models.CASCADE, blank=True, null=True)


class ImageManager(models.Manager):
    def delete(self):
        for obj in self.get_queryset():
            obj.delete()


class Image(models.Model):
    image_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(AppUser, on_delete=models.CASCADE)
    image = models.ImageField()
    date_upload = models.DateField(auto_now_add=True)

    objects = ImageManager()

    def delete(self, using=None, keep_parents=False):
        self.image.storage.delete(self.image.name)
        super().delete()


""" Only delete the file if no other instances of that model are using it"""


def delete_file_if_unused(model, instance, field, instance_file_field):
    dynamic_field = {}
    dynamic_field[field.name] = instance_file_field.name
    other_refs_exist = model.objects.filter(**dynamic_field).exclude(pk=instance.pk).exists()
    if not other_refs_exist:
        instance_file_field.delete(False)


""" Whenever ANY model is deleted, if it has a file field on it, delete the associated file too"""


@receiver(post_delete)
def delete_files_when_row_deleted_from_db(sender, instance, **kwargs):
    for field in sender._meta.concrete_fields:
        if isinstance(field, models.FileField):
            instance_file_field = getattr(instance, field.name)
            delete_file_if_unused(sender, instance, field, instance_file_field)


""" Delete the file if something else get uploaded in its place"""


@receiver(pre_save)
def delete_files_when_file_changed(sender, instance, **kwargs):
    # Don't run on initial save
    if not instance.pk:
        return
    for field in sender._meta.concrete_fields:
        if isinstance(field, models.FileField):
            # its got a file field. Let's see if it changed
            try:
                instance_in_db = sender.objects.get(pk=instance.pk)
            except sender.DoesNotExist:
                # We are probably in a transaction and the PK is just temporary
                # Don't worry about deleting attachments if they aren't actually saved yet.
                return
            instance_in_db_file_field = getattr(instance_in_db, field.name)
            instance_file_field = getattr(instance, field.name)
            if instance_in_db_file_field.name != instance_file_field.name:
                delete_file_if_unused(sender, instance, field, instance_in_db_file_field)

from django.contrib import admin
from  user_api.models import *

admin.site.register(AppUser)
admin.site.register(Profile)
admin.site.register(Social)
admin.site.register(Image)
admin.site.register(CustomUri)
# Register your models here.

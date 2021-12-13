from django.contrib import admin
from .models import User

# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'username')
    list_filter = ('is_superuser',)
    search_fields = ('email', 'username')


admin.site.register(User, UserAdmin)


from django.contrib import admin

from .models import QuickBooksToken, QuickBooksDiscoveryDocument


admin.site.register(QuickBooksToken)
admin.site.register(QuickBooksDiscoveryDocument)

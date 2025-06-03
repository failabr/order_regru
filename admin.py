from django.contrib import admin
from .models import ( Organization, UserProfile, Order,  OrderAttachment, ContactMessage)

admin.site.register(Organization)
admin.site.register(UserProfile)
admin.site.register(Order)
admin.site.register(OrderAttachment)
admin.site.register(ContactMessage)

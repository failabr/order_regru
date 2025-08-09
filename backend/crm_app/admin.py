from django.contrib import admin
from django.contrib.auth.models import User
from django.db.models import Q

from .models import (
    Organization,
    UserProfile,
    Order,
    OrderAttachment,
    ContactMessage,
    OrderOwner,  # прокси-модель из models.py
)

# --- Инлайн заказов, СОЗДАННЫХ пользователем ---
class OrdersCreatedInline(admin.TabularInline):
    model = Order
    fk_name = "created_by"   # ВАЖНО: у Order две FK на User, явный выбор
    extra = 0
    fields = ("order_number", "status", "full_name", "total_price", "received_date", "due_date", "assigned_to")
    show_change_link = True

# --- Инлайн заказов, НАЗНАЧЕННЫХ пользователю ---
class OrdersAssignedInline(admin.TabularInline):
    model = Order
    fk_name = "assigned_to"  # ВАЖНО
    extra = 0
    fields = ("order_number", "status", "full_name", "total_price", "received_date", "due_date", "created_by")
    show_change_link = True

@admin.register(OrderOwner)
class OrderOwnerAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "first_name", "last_name",
                    "orders_created_count", "orders_assigned_count", "orders_total")
    search_fields = ("username", "email", "first_name", "last_name")
    inlines = [OrdersCreatedInline, OrdersAssignedInline]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # показываем только тех, у кого есть хоть один созданный или назначенный заказ
        return qs.filter(Q(orders_created__isnull=False) | Q(assigned_orders__isnull=False)).distinct()

    def orders_created_count(self, obj):
        return obj.orders_created.count()
    orders_created_count.short_description = "Создано"

    def orders_assigned_count(self, obj):
        return obj.assigned_orders.count()
    orders_assigned_count.short_description = "Назначено"

    def orders_total(self, obj):
        return obj.orders_created.count() + obj.assigned_orders.count()
    orders_total.short_description = "Итого"

# --- Остальные модели как обычно ---
@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "code", "owner", "created_at")
    search_fields = ("name", "code", "owner__username")

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role")
    list_filter = ("role", "organization")
    search_fields = ("user__username",)

@admin.register(OrderAttachment)
class OrderAttachmentAdmin(admin.ModelAdmin):
    list_display = ("id", "order", "file", "uploaded_at")
    search_fields = ("order__order_number",)

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "subject", "created_at")
    search_fields = ("email", "subject")

# Убираем плоский список "Order" из меню, чтобы вместо него использовать "Ордеры"
try:
    admin.site.unregister(Order)
except admin.sites.NotRegistered:
    pass
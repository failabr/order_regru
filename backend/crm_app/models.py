from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now
from datetime import timedelta
import uuid
from django.db import models


def generate_unique_code():
    """Генерирует уникальный 10-значный код, проверяя, нет ли его уже в базе"""
    while True:
        new_code = uuid.uuid4().hex[:10].upper()  # Генерируем случайный код
        if not Organization.objects.filter(code=new_code).exists():  # Проверяем уникальность
            return new_code

class Organization(models.Model):
    id = models.BigAutoField(primary_key=True)  # ✅ Уникальный ID
    name = models.CharField(max_length=255)  # ✅ Разрешаем одинаковые названия
    code = models.CharField(max_length=10, unique=True)  # ✅ Код компании (уникальный)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_organizations', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """Гарантируем уникальный код перед сохранением"""
        if not self.code:
            self.code = generate_unique_code()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} (ID: {self.id})"
    

class UserProfile(models.Model):
    """Профиль пользователя с ролями"""
    ROLE_CHOICES = [
        ('individual', 'Индивидуал'),  # Новый пользователь
        ('owner', 'Владелец'),  # Создатель организации
        ('manager', 'Менеджер'),  # Член организации
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(
        Organization, on_delete=models.SET_NULL, related_name='users', null=True, blank=True
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='individual')  # Теперь по умолчанию 'individual'

    def become_owner(self, organization):
        """Метод делает пользователя владельцем организации"""
        self.organization = organization
        self.role = 'owner'
        self.save()

    def join_organization(self, organization):
        """Метод делает пользователя менеджером в организации"""
        self.organization = organization
        self.role = 'manager'
        self.save()

    def leave_organization(self):
        """Метод выхода из организации"""
        self.organization = None
        self.role = 'individual'  # Если пользователь вышел, он снова становится "Индивидуалом"
        self.save()

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"

class Order(models.Model):
    """Модель заказа"""
    STATUS_CHOICES = [
        ('new', 'Новый'),
        ('in_progress', 'В работе'),
        ('completed', 'Завершён'),
        ('cancelled', 'Отменён'),
    ]

    order_number = models.IntegerField(null=True, blank=True)

    class Meta:
        unique_together = ('order_number', 'organization', 'created_by')



    full_name = models.CharField(max_length=255, null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    product = models.CharField(max_length=255, null=True, blank=True)
    manufacturing_days = models.IntegerField(null=True, blank=True)

    received_date = models.DateField(blank=True, null=True) 
    due_date = models.DateField(null=True, blank=True)
    prepayment = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, related_name='orders', null=True, blank=True)
    assigned_to = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,blank=True,related_name='assigned_orders',help_text='Назначенный менеджер для контроля заказа')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='orders_created')
    
   

    def save(self, *args, **kwargs):
        # Если дата получения не установлена, устанавливаем текущую дату
        if self.received_date is None:
            self.received_date = now().date()


        # Если не установлена due_date и задано количество рабочих дней
        if not self.due_date and self.manufacturing_days:
            days_to_add = self.manufacturing_days
            current_date = self.received_date
            while days_to_add > 0:
                current_date += timedelta(days=1)
                # Считаем только рабочие дни (Пн-Пт)
                if current_date.weekday() < 5:
                    days_to_add -= 1
            self.due_date = current_date

        if self.order_number is None:
            if self.organization:
                last_order = Order.objects.filter(
                    organization=self.organization
                ).order_by('-order_number').first()
            else:
                last_order = Order.objects.filter(
                    created_by=self.created_by,
                    organization__isnull=True
                ).order_by('-order_number').first()

            self.order_number = (last_order.order_number + 1) if last_order else 1

        super().save(*args, **kwargs)


def attachment_directory_path(instance, filename):
    # Получаем номер заказа
    order_number = instance.order.order_number
    # Получаем уникальный идентификатор пользователя (например, username)
    user_code = instance.order.created_by.username  # или другой уникальный код
    # Формируем новое имя файла, добавляя номер заказа перед исходным именем
    new_filename = f"{order_number}_{filename}"
    # Полный путь: файлы сохраняются в каталоге attachments/<user_code>/
    return f'attachments/{user_code}/{new_filename}'






class OrderAttachment(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to=attachment_directory_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    

    def __str__(self):
        return f"Вложение для заказа #{self.order.order_number}"





class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    attachment = models.FileField(upload_to='contact_attachments/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.subject} от {self.email}"

class FurnitureType(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    base_labor_cost = models.DecimalField(max_digits=10, decimal_places=2)
    complexity_factor = models.DecimalField(max_digits=3, decimal_places=2, default=1.00)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='furniture_types')
    purchased = models.BooleanField(default=False, verbose_name='Куплено')
    excel_file = models.FileField(upload_to='furniture_files/', null=True, blank=True)

    def __str__(self):
        return self.name



from django.contrib.auth.models import User

class OrderOwner(User):
    """Прокси-модель для отображения пользователей с заказами в админке."""
    class Meta:
        proxy = True
        verbose_name = "Пользователь с заказами"
        verbose_name_plural = "Заказы"  # так будет называться пункт в меню
        # app_label можно не задавать; если хочешь видеть в блоке crm_app:
        # app_label = "crm_app"
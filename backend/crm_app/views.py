from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import viewsets, permissions
from .models import Order, UserProfile, OrderAttachment, Organization, FurnitureType
from .serializers import OrderSerializer, OrderAttachmentSerializer, FurnitureTypeSerializer
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.response import Response
from datetime import timedelta, datetime
from django.http import FileResponse, Http404
import os
from django.conf import settings
from urllib.parse import quote as urlquote, unquote
from django.utils.timezone import now
from django.db.utils import IntegrityError
from django.views.decorators.csrf import csrf_exempt
import logging
from django.db.models import Q 
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth import get_user_model
from django.conf import settings
from django.contrib.auth import authenticate
import requests
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.decorators import action
from django.core.mail import EmailMessage
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.core.files.base import ContentFile

from urllib.parse import urlparse, unquote
import logging





logger = logging.getLogger(__name__)





class OrderViewSet(viewsets.ModelViewSet):
    """
    ViewSet для управления заказами (Order).
    Поддерживает операции create, retrieve, update, partial_update, delete, list.
    """

    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        """Возвращаем заказы в зависимости от роли пользователя в организации с логированием"""
        if not self.request.user.is_authenticated:
            logger.info("Пользователь не аутентифицирован, возвращаем пустой QuerySet")
            return Order.objects.none()

        user = self.request.user
        user_profile = UserProfile.objects.filter(user=user).first()
        logger.info(f"Профиль пользователя: {user_profile}")
        if user_profile:
            logger.info(f"Найден профиль для пользователя {user.username}: {user_profile}")
        else:
            logger.info(f"Профиль для пользователя {user.username} не найден")

        if user_profile and user_profile.organization:
            logger.info(f"Пользователь {user.username} состоит в организации: {user_profile.organization}")
            if user_profile.role == 'owner':
                # Владелец — видит все заказы компании и свои личные
                orders = Order.objects.filter(
                    Q(organization=user_profile.organization) |
                    Q(created_by=user)
                ).distinct()
                logger.info(f"Владелец {user.username}; найдено заказов: {orders.count()}")
                return orders
            else:
                # Менеджер — видит свои и назначенные ему заказы
                orders = Order.objects.filter(
                    Q(created_by=user) | Q(assigned_to=user)
                ).distinct()
                logger.info(f"Менеджер {user.username}; найдено заказов: {orders.count()}")
                return orders
        else:
            # Пользователь без компании — видит только свои заказы
            orders = Order.objects.filter(created_by=user)
            logger.info(f"Индивидуал {user.username}; заказов: {orders.count()}")
            return orders

    def create(self, request, *args, **kwargs):
        user = request.user
        user_profile = UserProfile.objects.get(user=user)
        serializer = self.get_serializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            logger.warning("❌ Ошибки сериализатора: %s", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if user_profile.role != 'owner':
            serializer.validated_data.pop('assigned_to', None)

        self.perform_create(serializer)
        return Response(OrderSerializer(serializer.instance).data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        user = self.request.user
        user_profile = UserProfile.objects.get(user=user)
        organization = user_profile.organization if user_profile.organization else None

        if user_profile.role != 'owner':
            serializer.validated_data.pop('assigned_to', None)

        if 'order_number' in self.request.data and self.request.data['order_number']:
            order_number = serializer.validated_data.get('order_number')
            order = serializer.save(created_by=user, organization=organization, order_number=order_number)
        else:
            order = serializer.save(created_by=user, organization=organization)

        files = self.request.FILES.getlist("attachments")
        for file in files:
            OrderAttachment.objects.create(order=order, file=file)

    def perform_update(self, serializer):
        user = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        if user_profile.role != 'owner':
            serializer.validated_data.pop('assigned_to', None)

        order = serializer.save()

        files = self.request.FILES.getlist("attachments")
        for file in files:
            try:
                OrderAttachment.objects.create(order=order, file=file)
            except Exception as e:
                logger.error(f"Ошибка при сохранении файла {file.name}: {e}", exc_info=True)

    @action(detail=False, methods=['post'], url_path='update-furniture')
    @action(detail=False, methods=["post"], url_path="update-furniture")
    def update_furniture(self, request):
        """Обновление файла фурнитуры для заказа"""
        logger.info("📥 Получен запрос на обновление файла фурнитуры")
        
        try:
            if 'file' not in request.FILES:
                logger.error("❌ Файл не предоставлен в запросе")
                return Response({'error': 'Файл не предоставлен'}, status=status.HTTP_400_BAD_REQUEST)

            order_number = request.data.get('order_number')
            original_file_url = request.data.get('original_file_url')

            if not order_number or not original_file_url:
                logger.error("❌ Не указан номер заказа или URL оригинального файла")
                return Response({'error': 'Не указан номер заказа или URL оригинального файла'}, status=status.HTTP_400_BAD_REQUEST)

            # Правильно извлекаем путь из URL
            parsed = urlparse(original_file_url)
            file_path = parsed.path.replace('/media/', '')  # Удаляет только /media/, а не attachments
            file_path = unquote(file_path)

            if not default_storage.exists(file_path):
                logger.error(f"❌ Оригинальный файл не найден: {file_path}")
                return Response({'error': 'Оригинальный файл не найден'}, status=status.HTTP_404_NOT_FOUND)

            # Заменяем содержимое файла новым
            new_file = request.FILES['file']
            logger.info(f"💾 Перезаписываем файл: {file_path}")
            default_storage.delete(file_path)
            default_storage.save(file_path, ContentFile(new_file.read()))
            logger.info(f"✅ Файл успешно обновлён: {file_path}")

            return Response({
                'success': True,
                'message': 'Файл успешно обновлён',
                'file_path': file_path
            })

        except Exception as e:
            logger.error(f"❌ Ошибка при сохранении файла: {str(e)}", exc_info=True)
            return Response({
                'success': False,
                'message': f'Ошибка при сохранении файла: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OrderAttachmentViewSet(viewsets.ModelViewSet):
    queryset = OrderAttachment.objects.all()
    serializer_class = OrderAttachmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return OrderAttachment.objects.filter(order__created_by=self.request.user)

@api_view(["POST"])
@permission_classes([AllowAny])
def register_user(request):
    """Регистрация пользователя + подтверждение email"""
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")
    confirm_password = request.data.get("confirm_password")
    recaptcha_token = request.data.get("recaptcha")

    if not username or not email or not password or not confirm_password:
        return Response({"error": "Заполните все поля"}, status=status.HTTP_400_BAD_REQUEST)

    if password != confirm_password:
        return Response({"error": "Пароли не совпадают"}, status=status.HTTP_400_BAD_REQUEST)

    if len(password) < 8:
        return Response({"error": "Пароль должен быть не менее 8 символов"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({"error": "Этот логин уже занят"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({"error": "Этот email уже зарегистрирован"}, status=status.HTTP_400_BAD_REQUEST)

    # Проверка reCAPTCHA только если не в режиме разработки
    if not settings.DEBUG or recaptcha_token != 'development_mode':
        recaptcha_secret = settings.RECAPTCHA_PRIVATE_KEY
        recaptcha_response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": recaptcha_secret, "response": recaptcha_token}
        )
        recaptcha_result = recaptcha_response.json()
        if not recaptcha_result.get("success"):
            return Response({"error": "Ошибка reCAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)

    # ⛔ Создаём неактивного пользователя
    user = User.objects.create_user(username=username, email=email, password=password)
    user.is_active = False
    user.save()
    UserProfile.objects.get_or_create(user=user)

    try:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"

        subject = "Подтвердите вашу почту на ORDIO"
        message = render_to_string("emails/activation_email.html", {
            "username": user.username,
            "activation_link": activation_link,
        })

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

    except BadHeaderError:
        return Response({"error": "Ошибка заголовка почты"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        print("❌ Ошибка при отправке письма:", str(e))
        return Response({"error": "Ошибка при отправке письма. Проверьте настройки почты."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"message": "✅ Регистрация успешна. Проверьте почту для подтверждения."}, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([AllowAny])
def activate_user(request, uidb64, token):
    print(f"📥 Активация uid: {uidb64}")
    print(f"📥 token: {token}")
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        print(f"🔎 Найден пользователь: {user.username}, is_active={user.is_active}")
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        print("❌ Пользователь не найден или uid некорректен")
        return Response({"error": "Неверная ссылка активации"}, status=400)

    if user.is_active:
        return Response({"message": "Пользователь уже активирован"}, status=200)

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        print("✅ Токен валидный, пользователь активирован")
        return Response({"message": "Пользователь успешно активирован"}, status=200)
    else:
        print("❌ Невалидный токен")
        return Response({"error": "Ссылка устарела или недействительна"}, status=400)



@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """🔐 Вход с reCAPTCHA для веба и без неё для мобильных приложений"""
    username = request.data.get("username")
    password = request.data.get("password")
    recaptcha_token = request.data.get("recaptcha")

    logger.info(f"Попытка входа: {username}")

    if not all([username, password]):
        return Response({"error": "Все поля обязательны."}, status=status.HTTP_400_BAD_REQUEST)

    # 🔍 Определим, что это мобильное приложение
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile_client = 'reactnative' in user_agent or 'okhttp' in user_agent or 'ordioapp' in user_agent \
                   or recaptcha_token == 'skip_for_mobile'

    # ✅ Проверка reCAPTCHA для веба (если не в режиме mobile или dev)
    if not is_mobile_client:
        if not recaptcha_token:
            return Response({"error": "Отсутствует токен reCAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)

        recaptcha_secret = settings.RECAPTCHA_PRIVATE_KEY
        try:
            recaptcha_response = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": recaptcha_secret, "response": recaptcha_token}
            )
            recaptcha_result = recaptcha_response.json()
            if not recaptcha_result.get("success"):
                logger.warning("Ошибка проверки reCAPTCHA")
                return Response({"error": "Ошибка reCAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)
        except requests.RequestException as e:
            logger.error(f"Ошибка подключения к Google reCAPTCHA: {e}")
            return Response({"error": "Ошибка проверки reCAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)

    # 🔐 Аутентификация
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        logger.warning(f"Пользователь не найден: {username}")
        return Response({"non_field_errors": ["Неверный логин или пароль"]}, status=status.HTTP_400_BAD_REQUEST)

    if not user.check_password(password):
        logger.warning(f"Неверный пароль для пользователя: {username}")
        return Response({"non_field_errors": ["Неверный логин или пароль"]}, status=status.HTTP_400_BAD_REQUEST)

    if not user.is_active:
        logger.warning(f"Аккаунт не активирован: {username}")
        return Response({
            "error": "Аккаунт не активирован.",
            "resend": True,
            "username": user.username,
            "email": user.email
        }, status=status.HTTP_403_FORBIDDEN)

    # 🎫 Токен
    token, _ = Token.objects.get_or_create(user=user)
    logger.info(f"Успешный вход: {username}")
    return Response({"token": token.key}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def resend_activation_email(request):
    email = request.data.get("email")

    try:
        user = User.objects.get(email=email)
        if user.is_active:
            return Response({"message": "Аккаунт уже активирован"}, status=400)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"

        subject = "Повторная активация аккаунта"
        message = render_to_string("emails/activation_email.html", {
            "username": user.username,
            "activation_link": activation_link,
        })

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        return Response({"message": "Письмо отправлено повторно"}, status=200)

    except User.DoesNotExist:
        return Response({"error": "Пользователь не найден"}, status=404)



"""Создаем новую организацию"""
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_organization(request):
    try:
        user = request.user
        print(f"🔹 Запрос на создание компании от: {user.username}")

        # Проверяем, состоит ли пользователь уже в компании
        profile = UserProfile.objects.get(user=user)
        if profile.organization is not None:
            return Response(
                {"error": "У Вас уже есть компания, на данный момент можно создать только одну компанию на 1 аккаунт"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Проверяем, передано ли название компании
        name = request.data.get("name")
        if not name:
            return Response({"error": "Введите название компании"}, status=status.HTTP_400_BAD_REQUEST)

        # Создаём компанию
        organization = Organization.objects.create(name=name, owner=user)

        # Обновляем профиль пользователя
        profile.organization = organization
        profile.role = 'owner'
        profile.save()

        # Обновляем все заказы пользователя, у которых не указана организация
        updated_count = Order.objects.filter(created_by=user, organization__isnull=True).update(organization=organization)
        print(f"Обновлено заказов: {updated_count}")

        print(f"✅ Компания создана: {name} | ID: {organization.id} | Код: {organization.code}")
        return Response({"message": "Компания создана", "id": organization.id, "code": organization.code}, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        print(f"❌ IntegrityError: {str(e)}")
        return Response({"error": "Ошибка: код компании уже существует"}, status=status.HTTP_400_BAD_REQUEST)
    except UserProfile.DoesNotExist:
        print(f"❌ Ошибка: профиль пользователя {user.username} не найден!")
        return Response({"error": "Ваш профиль не найден"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"❌ Ошибка сервера: {str(e)}")
        return Response({"error": f"Ошибка сервера: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def join_organization(request):
    """✅ Присоединение к организации по коду"""
    code = request.data.get("code")
    
    print(f"Получен код для присоединения: '{code}'")   #проверка кода 
    try:
        organization = Organization.objects.get(code=code)
    except Organization.DoesNotExist:
        return Response({"error": "Компания не найдена"}, status=status.HTTP_404_NOT_FOUND)

    profile = UserProfile.objects.get(user=request.user)
    profile.organization = organization
    profile.role = 'manager'
    profile.save()

    # Обновляем все заказы пользователя, у которых не установлена организация
    updated_count = Order.objects.filter(created_by=request.user).update(organization=organization)
    print(f"Обновлено заказов: {updated_count}")

    return Response({"message": f"Вы присоединились к {organization.name}"}, status=status.HTTP_200_OK)


"""✅ Покинуть организацию"""
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def leave_organization(request):
    """Выход пользователя из компании"""
    try:
        profile = UserProfile.objects.get(user=request.user)

        # Если пользователь уже не в организации
        if not profile.organization:
            return Response({"error": "Вы не состоите в компании"}, status=status.HTTP_400_BAD_REQUEST)

        # Если пользователь владелец, выход невозможен
        if profile.role == 'owner':
            return Response(
                {
                    "error": "Вы являетесь владельцем компании. Перед выходом измените владельца или удалите компанию."
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Обновляем профиль: удаляем привязку к организации и меняем роль
        profile.organization = None
        profile.role = 'individual'  # Теперь он снова индивидуальный пользователь
        profile.save()

        return Response({"message": "Вы вышли из компании"}, status=status.HTTP_200_OK)

    except UserProfile.DoesNotExist:
        return Response({"error": "Профиль пользователя не найден"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": f"Ошибка сервера: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_info(request):
    """✅ Получить данные текущего пользователя"""
    profile = UserProfile.objects.get(user=request.user)

    return Response({
        "username": profile.user.username,
        "organization": profile.organization.name if profile.organization else "Нет",
        "organization_code": profile.organization.code if profile.organization else None,
        "role": profile.role,
        "role_display": profile.get_role_display(),
    })

@api_view(["GET"])
def download_attachment(request, file_path):
    """✅ Принудительное скачивание файлов"""
    try:
        file_path = os.path.join(settings.MEDIA_ROOT, file_path)
        file_name = os.path.basename(file_path)

        response = FileResponse(open(file_path, "rb"), as_attachment=True)
        response["Content-Disposition"] = f'attachment; filename="{urlquote(file_name)}"'
        return response
    except FileNotFoundError:
        raise Http404("Файл не найден")
    

   
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def delete_organization(request):
    """
    Удаление организации. Доступно только владельцу.
    После удаления всем пользователям, включая владельца, сбрасывается роль на 'individual' и organization=None.
    """
    profile = UserProfile.objects.get(user=request.user)

    if not profile.organization:
        return Response({"error": "Вы не состоите в организации"}, status=status.HTTP_400_BAD_REQUEST)

    if profile.role != 'owner':
        return Response({"error": "Удалять организацию может только владелец"}, status=status.HTTP_403_FORBIDDEN)

    organization = profile.organization
    organization_name = organization.name

    # Сохраняем ID организации до удаления
    org_id = organization.id

    # Удаляем организацию
    organization.delete()

    # Обновляем всех пользователей, которые были в этой организации
    UserProfile.objects.filter(organization__isnull=True, role__in=['owner', 'manager']).update(role='individual')

    return Response(
        {"message": f"Организация '{organization_name}' удалена. Все пользователи переведены в режим 'individual'."},
        status=status.HTTP_200_OK
    )



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_my_managers(request):
    """✅ Возвращает всех менеджеров в той же компании, кроме владельца"""
    profile = UserProfile.objects.get(user=request.user)

    if not profile.organization:
        return Response([])  # Нет компании — никого не возвращаем

    managers = User.objects.filter(
        userprofile__organization=profile.organization,
        userprofile__role='manager'
    ).values("id", "username")

    return Response(list(managers))

"""востановление пароля"""
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_request(request):
    """
    Принимает email и, если пользователь существует, отправляет письмо со ссылкой для сброса пароля.
    """
    email = request.data.get("email")
    if not email:
        return Response({"error": "Email обязателен"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Не раскрываем информацию о существовании пользователя
        return Response({"message": "Если пользователь с таким email существует, письмо отправлено."}, status=status.HTTP_200_OK)

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    reset_link = f"{settings.FRONTEND_URL}/password-reset-confirm/{uid}/{token}/"
    
    subject = "Восстановление пароля"
    message = render_to_string("emails/password_reset_email.html", {
        "user": user,
        "reset_link": reset_link,
    })
    
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
    
    return Response({"message": "Если пользователь с таким email существует, письмо отправлено."}, status=status.HTTP_200_OK)

"""обновление пароля после востановления"""
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_confirm(request, uidb64, token):
    """
    Endpoint для подтверждения сброса пароля.
    Ожидает в теле запроса:
      - new_password: новый пароль
      - confirm_password: подтверждение нового пароля
    """
    new_password = request.data.get("new_password")
    confirm_password = request.data.get("confirm_password")

    if not new_password or not confirm_password:
        return Response({"error": "Введите новый пароль и его подтверждение."}, status=status.HTTP_400_BAD_REQUEST)

    if new_password != confirm_password:
        return Response({"error": "Пароли не совпадают."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({"error": "Некорректный идентификатор пользователя."}, status=status.HTTP_400_BAD_REQUEST)

    if not default_token_generator.check_token(user, token):
        return Response({"error": "Неверный или устаревший токен."}, status=status.HTTP_400_BAD_REQUEST)

    # Устанавливаем новый пароль
    user.set_password(new_password)
    user.save()

    return Response({"message": "Пароль успешно сброшен."}, status=status.HTTP_200_OK)

"""сообщение для разработчика"""
@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([])  # Можно ограничить доступ, если требуется
def contact_message(request):
    name = request.data.get("name")
    email = request.data.get("email")
    subject = request.data.get("subject")
    message_body = request.data.get("message")
    attachment = request.FILES.get("attachment")

    if not all([name, email, subject, message_body]):
        return Response({"error": "Все поля обязательны"}, status=status.HTTP_400_BAD_REQUEST)

    # Составляем тело письма
    full_message = (
        f"От: {name} <{email}>\n\n"
        f"Тема: {subject}\n\n"
        f"Сообщение:\n{message_body}"
    )

    try:
        # Если нужно прикреплять файл, понадобится более сложная логика, например, с использованием EmailMessage
        # Простой вариант без вложения:
        email_message = EmailMessage(
            subject,
            full_message,
            settings.DEFAULT_FROM_EMAIL,
            ['abrarov9@gmail.com']
        )
        if attachment:
            email_message.attach(attachment.name, attachment.read(), attachment.content_type)
        email_message.send()

        return Response({"message": "Сообщение успешно отправлено"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": f"Ошибка при отправке письма: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FurnitureTypeViewSet(viewsets.ModelViewSet):
    serializer_class = FurnitureTypeSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_queryset(self):
        user_profile = self.request.user.userprofile
        return FurnitureType.objects.filter(organization=user_profile.organization)

    def perform_create(self, serializer):
        serializer.save(organization=self.request.user.userprofile.organization)

    def perform_update(self, serializer):
        instance = self.get_object()
        # Сохраняем старый файл, если новый не предоставлен
        if 'excel_file' not in self.request.FILES and instance.excel_file:
            serializer.validated_data['excel_file'] = instance.excel_file
        serializer.save()

    @action(detail=True, methods=['PATCH'])
    def toggle_purchased(self, request, pk=None):
        furniture = self.get_object()
        furniture.purchased = not furniture.purchased
        furniture.save()
        return Response({
            'id': furniture.id,
            'purchased': furniture.purchased
        })
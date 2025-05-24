
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from crm_app.views import OrderViewSet
from rest_framework.authtoken.views import obtain_auth_token
from crm_app.views import register_user, create_organization, join_organization, leave_organization, user_info, delete_organization
from django.conf import settings
from django.conf.urls.static import static
from crm_app.views import download_attachment
from crm_app.views import OrderAttachmentViewSet
from crm_app.views import get_my_managers
from crm_app.views import activate_user
from django.urls import path
from crm_app import views
from django.views.generic import TemplateView
from crm_app.views import activate_user, resend_activation_email,login_view
from crm_app.views import password_reset_request
from crm_app.views import password_reset_confirm
from crm_app.views import contact_message
from django.urls import re_path


router = routers.DefaultRouter()
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'order-attachments', OrderAttachmentViewSet, basename='order-attachments')

urlpatterns = [
    
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api-token-auth/', obtain_auth_token),
    #path('api/api-token-auth/', obtain_auth_token),  # Стандартный путь для токенов DRF
    path("api/register/", register_user, name="register"),  # Добавляем эндпоинт регистрации
    path("media/download/<path:file_path>/", download_attachment, name="download_attachment"),
    path('api/create_organization/', create_organization),
    path('api/join_organization/', join_organization),
    path('api/leave_organization/', leave_organization),
    path('api/delete_organization/', delete_organization, name="delete_organization"),
    path('api/user_info/', user_info, name="user_info"),
    path("api/my_managers/", get_my_managers),
    path('api/activate/<uidb64>/<token>/', activate_user, name='activate_user'),
    path("api/resend-activation/", resend_activation_email, name="resend_activation"),
    path('api/login/', login_view, name='login'),
    path('api/password-reset/', password_reset_request, name='password_reset'),
    path('api/password-reset-confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('api/contact/', contact_message, name='contact_message'),
    re_path(r'^(?!api/|admin/|media/).*$', TemplateView.as_view(template_name="index.html")),


]
    





if settings.DEBUG:  # Только в режиме разработки!if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
 
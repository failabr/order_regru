from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'orders', views.OrderViewSet, basename='order')
router.register(r'attachments', views.OrderAttachmentViewSet)
router.register(r'materials', views.MaterialViewSet, basename='material')
router.register(r'components', views.ComponentViewSet, basename='component')
router.register(r'services', views.ServiceTypeViewSet, basename='service')
router.register(r'furniture-types', views.FurnitureTypeViewSet, basename='furniture-type')

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/register/', views.register_user, name='register'),
    path('api/login/', views.login_view, name='login'),
    path('api/create-organization/', views.create_organization, name='create-organization'),
    path('api/join-organization/', views.join_organization, name='join-organization'),
    path('api/leave-organization/', views.leave_organization, name='leave-organization'),
    path('api/delete-organization/', views.delete_organization, name='delete-organization'),
    path('api/user-info/', views.user_info, name='user-info'),
    path('api/download/<path:file_path>/', views.download_attachment, name='download-attachment'),
    path('furniture-types/<int:pk>/toggle-purchased/', views.FurnitureTypeViewSet.as_view({'patch': 'toggle_purchased'}), name='furniture-toggle-purchased'),
] 
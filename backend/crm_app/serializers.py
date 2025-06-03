# ✅ SERIALIZERS.PY
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Organization, UserProfile, Order, OrderAttachment, FurnitureType
from .models import ContactMessage

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'

class OrderAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderAttachment
        fields = ['id', 'file', 'uploaded_at']

class OrderSerializer(serializers.ModelSerializer):
    attachments = OrderAttachmentSerializer(many=True, read_only=True)
    assigned_to = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False, allow_null=True)

    # Новое поле для передачи имени создателя заказа (автора)
    created_by_username = serializers.SerializerMethodField()


    class Meta:
        model = Order
        fields = '__all__'
        extra_kwargs = {
            'order_number': {'required': False},
            'organization': {'required': False},
            'created_by': {'read_only': True},
            #'received_date': {'read_only': True},
            'due_date': {'read_only': True},
        }

    def get_created_by_username(self, obj):
        return obj.created_by.username if obj.created_by else None



    def validate(self, data):
        request = self.context.get('request')
        user_profile = UserProfile.objects.get(user=request.user)

        if user_profile.role != 'owner' and 'assigned_to' in data:
            data.pop('assigned_to')  # ❌ Менеджерам нельзя передавать контролёра

        return data

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user
        user_profile = UserProfile.objects.get(user=user)

        # 🔒 Только владелец может передавать assigned_to
        if user_profile.role != 'owner':
            validated_data.pop('assigned_to', None)

        validated_data.pop('uploaded_files', None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        request = self.context.get('request')
        user = request.user
        user_profile = UserProfile.objects.get(user=user)

        # 🔒 Только владелец может изменять assigned_to
        if user_profile.role != 'owner':
            validated_data.pop('assigned_to', None)

        validated_data.pop('uploaded_files', None)
        return super().update(instance, validated_data)


class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = '__all__'

class FurnitureTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = FurnitureType
        fields = ['id', 'name', 'description', 'base_labor_cost', 'complexity_factor', 'organization', 'purchased', 'excel_file']
        read_only_fields = ['organization']


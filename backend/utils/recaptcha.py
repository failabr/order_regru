import requests
from django.conf import settings

def verify_recaptcha_v3(token: str) -> bool:
    """Проверка reCAPTCHA v3"""
    if settings.DEBUG and token == "development_mode":
        return True  # Пропускаем проверку в режиме отладки

    secret_key = settings.RECAPTCHA_PRIVATE_KEY
    response = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": secret_key, "response": token}
    )
    result = response.json()
    return result.get("success", False) and result.get("score", 0) >= 0.5
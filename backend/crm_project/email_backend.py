# crm_project/email_backend.py

import ssl
import certifi
import smtplib
from django.core.mail.backends.smtp import EmailBackend

class CustomEmailBackend(EmailBackend):
    def open(self):
        if self.connection:
            return False

        try:
            self.connection = smtplib.SMTP(
                self.host,
                self.port,
                timeout=self.timeout,
                local_hostname=None  # ← безопасно заменить
            )
            self.connection.ehlo()

            if self.use_tls:
                context = ssl.create_default_context(cafile=certifi.where())
                self.connection.starttls(context=context)
                self.connection.ehlo()

            if self.username and self.password:
                self.connection.login(self.username, self.password)

            return True
        except Exception:
            if not self.fail_silently:
                raise
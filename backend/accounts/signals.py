import time

from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from .authentication import LOGIN_AT_SESSION_KEY


@receiver(user_logged_in)
def record_login_time(sender, request, user, **kwargs):
    """Start the absolute session timeout for every login path."""
    if request is not None and hasattr(request, "session"):
        request.session[LOGIN_AT_SESSION_KEY] = time.time()

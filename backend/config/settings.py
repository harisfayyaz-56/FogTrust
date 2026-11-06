"""
FogTrust broker settings.

Security-relevant values come from environment variables (see .env.example)
so that no secret is ever committed to Git. Defaults are the *safe* choice:
DEBUG is off unless explicitly turned on, and a missing secret key stops the
server instead of silently using a weak one.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent  # .../backend
REPO_ROOT = BASE_DIR.parent

load_dotenv(REPO_ROOT / ".env")

FOGTRUST_VERSION = "0.1.0"


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be an integer") from exc


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
DEBUG = env_bool("DJANGO_DEBUG", False)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY.startswith("replace-me"):
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY is not set. Copy .env.example to .env and generate a key "
        "(see README, 'First-time setup')."
    )

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    # FogTrust apps
    "core",
    "accounts",
    "audit",
]

MIDDLEWARE = [
    "core.middleware.RequestIdMiddleware",  # first, so every log line and error has an ID
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ---------------------------------------------------------------------------
# Database (SQLite so the project runs on any laptop)
# ---------------------------------------------------------------------------
_sqlite_path = Path(os.environ.get("SQLITE_PATH", "db.sqlite3"))
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": _sqlite_path if _sqlite_path.is_absolute() else BASE_DIR / _sqlite_path,
        "OPTIONS": {
            # Writers take the lock at BEGIN, so "read last audit event, insert next"
            # can never interleave between two requests (audit/services.py).
            "transaction_mode": "IMMEDIATE",
            "timeout": 20,
        },
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Authentication and passwords
# ---------------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"  # custom model set from day one (cannot be changed safely later)

# Argon2 first: memory-hard, the current OWASP recommendation.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Sessions and cookies
# ---------------------------------------------------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.db"  # survives server restart
SESSION_COOKIE_AGE = env_int("SESSION_IDLE_TIMEOUT_SECONDS", 1800)
# Hard limit after login, however active the session is (accounts/authentication.py).
SESSION_ABSOLUTE_TIMEOUT_SECONDS = env_int("SESSION_ABSOLUTE_TIMEOUT_SECONDS", 8 * 3600)
SESSION_SAVE_EVERY_REQUEST = True  # sliding window: expires after N seconds of inactivity
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True  # JavaScript cannot read the session cookie
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_NAME = "fogtrust_session"

COOKIE_SECURE = env_bool("COOKIE_SECURE", False)
SESSION_COOKIE_SECURE = COOKIE_SECURE
CSRF_COOKIE_SECURE = COOKIE_SECURE

# The React app reads this cookie and sends it back in the X-CSRFToken header,
# so it must NOT be HttpOnly. The session cookie (above) is HttpOnly.
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
CSRF_FAILURE_VIEW = "core.views.csrf_failure"

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

# ---------------------------------------------------------------------------
# Input size limits (T-final: oversized input)
# ---------------------------------------------------------------------------
DATA_UPLOAD_MAX_MEMORY_SIZE = env_int("MAX_REQUEST_BODY_BYTES", 256 * 1024)
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200
FILE_UPLOAD_MAX_MEMORY_SIZE = DATA_UPLOAD_MAX_MEMORY_SIZE

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    # Humans log in with a session cookie. Nodes use signed requests (added in Week 3).
    "DEFAULT_AUTHENTICATION_CLASSES": ["accounts.authentication.FogTrustSessionAuthentication"],
    # Deny by default: every endpoint needs a logged-in user unless it opts out explicitly.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "EXCEPTION_HANDLER": "core.exceptions.api_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/min",
        "user": "600/min",
        # Scoped rates used by specific endpoints (Week 2 and 3)
        "login": os.environ.get("LOGIN_RATE_LIMIT", "5/min"),
        "login_username": os.environ.get("LOGIN_USERNAME_RATE_LIMIT", "20/hour"),
        "enroll": "10/min",
        "heartbeat": "120/min",
    },
    "DEFAULT_PAGINATION_CLASS": "core.pagination.StandardPagination",
    "PAGE_SIZE": 25,
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
}

# Throttle counters live in this cache. Local memory is fine for one server process.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "fogtrust",
    }
}

# ---------------------------------------------------------------------------
# Internationalisation and time
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"  # all stored timestamps are UTC; the dashboard converts for display
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# ---------------------------------------------------------------------------
# Logging (console). Secrets must never be passed to loggers.
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "loggers": {
        "fogtrust": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration for Exam Portal"""

    # Flask Config
    SECRET_KEY = os.environ.get('SECRET_KEY')
    DEBUG = os.environ.get('FLASK_DEBUG') == 'True'

    # SQLAlchemy Config
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Config
    JWT_SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    JWT_ERROR_MESSAGE_KEY = 'message'

    # Redis Config
    REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_URL = os.environ.get('REDIS_URL', f'redis://{REDIS_HOST}:{REDIS_PORT}/0')

    # Celery Config
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', REDIS_URL)
    CELERY_TIMEZONE = 'UTC'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
    CELERY_BROKER_CONNECTION_MAX_RETRIES = 5
    CELERY_BROKER_CONNECTION_RETRY = True
    CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

    # Celery Config - using new-style keys
    broker_url = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', REDIS_URL)
    timezone = 'UTC'
    task_serializer = 'json'
    result_serializer = 'json'
    accept_content = ['json']
    task_track_started = True
    task_time_limit = 30 * 60  # 30 minutes
    broker_connection_max_retries = 5
    broker_connection_retry = True
    broker_connection_retry_on_startup = True

    # Email Config (For Notifications and Reports)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = bool(int(os.environ.get('MAIL_USE_TLS', 0)))
    MAIL_USE_SSL = bool(int(os.environ.get('MAIL_USE_SSL', 0)))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

    # Admin Config
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

    # Caching Config (For Performance Optimization)
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_HOST = REDIS_HOST
    CACHE_REDIS_PORT = REDIS_PORT
    CACHE_REDIS_DB = 1
    CACHE_DEFAULT_TIMEOUT = 300
    CACHE_KEY_PREFIX = 'quizmaster_'
    CACHE_OPTIONS = {'socket_timeout': 5}

    # Session Expiry
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    # CORS (For Frontend Communication)
    CORS_HEADERS = 'Content-Type, Authorization'
    CORS_RESOURCES = {r"/api/*": {"origins": "*"}}
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = ['Authorization', 'Content-Type']
    
    # Export Folder
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    EXPORT_FOLDER = os.path.join(BASE_DIR, 'exports')
    
    # Google Chat Webhook Configuration
    GOOGLE_CHAT_WEBHOOK_URL = os.environ.get('GOOGLE_CHAT_WEBHOOK_URL', 'https://chat.googleapis.com/v1/spaces/AAAAcr74YrM/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=8XrUluRvFa_Qyr3yiBqMA-SJlDhpxA2Lo81lskhJV4w')
    
    # Job Configurations
    DAILY_REMINDER_HOUR = int(os.environ.get('DAILY_REMINDER_HOUR', 18))  # Default to 6 PM
    DAILY_REMINDER_MINUTE = int(os.environ.get('DAILY_REMINDER_MINUTE', 0))  # Default to 0 minutes

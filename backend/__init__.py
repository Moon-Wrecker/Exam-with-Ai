from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_caching import Cache
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from dotenv import load_dotenv
import os
import logging
from datetime import timedelta
import time
from celery.schedules import crontab

# Load environment variables
load_dotenv()

# Import the db instance from database.py
from .database import db
from .config import Config

# Initialize extensions
jwt = JWTManager()
cache = Cache()
mail = Mail()

# Don't import tasks at module level to avoid circular imports
# from .tasks import celery, configure_celery

# Token blocklist
token_blocklist = set()

# Function to clear all cache
def clear_all_cache():
    """
    Clear all cache entries
    This is useful for maintainance or when making major data changes
    """
    try:
        cache.clear()
        return True
    except Exception as e:
        logging.error(f"Error clearing cache: {str(e)}")
        return False

def create_app(config_class=Config):
    app = Flask(__name__)
    
    # Configure logging
    if not app.debug:
        # In production, log to file
        handler = logging.FileHandler('app.log')
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
    else:
        # In development, log to console
        # First remove any existing handlers to prevent duplicate logs
        for handler in app.logger.handlers:
            app.logger.removeHandler(handler)
        handler = logging.StreamHandler()
        # Set to WARNING level to reduce debug output
        handler.setLevel(logging.WARNING)
        app.logger.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
    
    # Log application startup - removed duplicated print statement
    app.logger.info("Starting Exam Portal application")
    
    # Load configuration
    app.config.from_object(config_class)
    
    # Ensure DATABASE_URL is available - removed duplicated print statement
    app.logger.info(f"DATABASE_URL: {os.environ.get('DATABASE_URL')}")
    
    # Additional JWT configuration
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Shorter access token lifetime
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_IDENTITY_CLAIM'] = 'sub'
    app.config['JWT_COOKIE_SECURE'] = not app.debug  # Secure cookies in production
    
    # Basic cache config - Use Redis if available, otherwise SimpleCache
    if os.environ.get('REDIS_URL'):
        app.config.update({
            'CACHE_TYPE': 'RedisCache',
            'CACHE_REDIS_URL': os.environ.get('REDIS_URL'),
            'CACHE_DEFAULT_TIMEOUT': 300,
            'CACHE_KEY_PREFIX': 'quizmaster_',
            'CACHE_OPTIONS': {'socket_timeout': 5}
        })
    else:
        # Keep it simple for SimpleCache - no Redis-specific options
        app.config['CACHE_TYPE'] = 'SimpleCache'
        app.config['CACHE_DEFAULT_TIMEOUT'] = 300
        # Ensure no Redis options are passed to SimpleCache
        app.config.pop('CACHE_OPTIONS', None)
        app.config.pop('CACHE_REDIS_URL', None)
        app.config.pop('CACHE_KEY_PREFIX', None)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize cache
    cache.init_app(app)
    
    # Initialize JWT
    jwt.init_app(app)
    
    # Initialize Mail
    mail.init_app(app)
    
    # Configure and initialize Celery - import here to avoid circular imports
    from .tasks import init_celery
    celery = init_celery(app)
    
    # Configure Celery Beat schedule
    celery.conf.beat_schedule = {
        'daily-reminder': {
            'task': 'backend.tasks.send_daily_reminders',
            'schedule': crontab(
                hour=app.config.get('DAILY_REMINDER_HOUR', 18),
                minute=app.config.get('DAILY_REMINDER_MINUTE', 0)
            ),
        },
        'monthly-report': {
            'task': 'backend.tasks.send_monthly_reports',
            'schedule': crontab(
                0, 0, day_of_month=1  # Run at midnight on the first day of each month
            ),
        },
    }
    
    # Ensure exports directory exists
    os.makedirs(app.config.get('EXPORT_FOLDER'), exist_ok=True)
    
    # Setup blocklist
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return jti in token_blocklist
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"message": "Token has expired", "error": "token_expired"}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"message": "Invalid token", "error": "invalid_token"}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({"message": "Missing authorization token", "error": "authorization_required"}), 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({"message": "Token has been revoked", "error": "token_revoked"}), 401
    
    # Setup CORS properly for API routes
    CORS(app, 
         resources={r"/api/*": {"origins": ["http://localhost:8080", "http://localhost:8081"]}},
         supports_credentials=True, 
         expose_headers=['Content-Type', 'Authorization'],
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    
    # Register blueprints
    with app.app_context():
        # Register API blueprint
        from .api import blu as api_blueprint
        app.register_blueprint(api_blueprint)
        
        # Custom unauthorized handler for API endpoints
        @app.errorhandler(401)
        def unauthorized_handler(error):
            if request.path.startswith('/api/'):
                return jsonify({
                    "error": "Authentication required",
                    "message": "Please ensure your token is valid and properly set in the Authorization header"
                }), 401
            return error
        
        # Log successful application initialization - removed duplicated print
        app.logger.info("Application initialized successfully")
    
    # Request logging middleware - disabled for less verbosity
    # @app.before_request
    # def log_request_info():
    #     """Log request details for monitoring and debugging"""
    #     app.logger.debug('Request: %s %s', request.method, request.path)
    #     app.logger.debug('Headers: %s', request.headers)
        
    # @app.after_request
    # def log_response_info(response):
    #     """Log response details for monitoring and debugging"""
    #     app.logger.debug('Response: %s %s %s', request.method, request.path, response.status)
    #     return response
        
    # Performance monitoring middleware - keep only slow request warnings
    @app.before_request
    def start_timer():
        """Start a timer for request duration tracking"""
        request._start_time = time.time()
        
    @app.after_request
    def log_request_time(response):
        """Log request duration for performance monitoring"""
        if hasattr(request, '_start_time'):
            duration = time.time() - request._start_time
            # Log requests that take longer than 0.5 seconds
            if duration > 0.5:
                app.logger.warning(
                    'Slow request: %s %s took %.2fs', 
                    request.method, request.path, duration
                )
        return response
        
    return app

# DON'T re-export user_datastore to avoid circular imports
# from .models import user_datastore
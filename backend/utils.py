from flask import current_app, jsonify, request, g, has_app_context
import redis
import json
from datetime import datetime, date
from flask_jwt_extended import decode_token, verify_jwt_in_request, get_jwt
from backend import cache  # Import cache from __init__.py
from functools import wraps
import logging
import time
import uuid

__all__ = [
    "cache_data",
    "get_cached_data",
    "roles_required",
    "verify_jwt",
    "verify_custom_token",
    "calculate_quiz_stats",
    "export_scores_csv",
    "generate_report_html",
    "generate_pdf",
    "send_email",
]

# Initialize Redis connection
redis_client = None

def get_redis_client():
    """Get the Redis client
    
    Returns:
        Redis client or None if available
    """
    from flask import current_app, g, has_app_context
    
    # First check if we have an application context
    if not has_app_context():
        return None
        
    try:
        # First try to use Flask-Caching redis client if available
        if hasattr(current_app, 'extensions') and 'cache' in current_app.extensions:
            cache = current_app.extensions['cache']
            if hasattr(cache, '_client'):
                # Some Flask-Caching backends have a _client attribute
                return cache._client
            
            # Try to access the Redis client in various ways depending on Flask-Caching version
            if hasattr(cache, 'cache'):
                if hasattr(cache.cache, '_write_client'):
                    return cache.cache._write_client
                
                # For Redis cluster configurations
                if hasattr(cache.cache, 'redis'):
                    return cache.cache.redis
        
        # Fallback to direct Redis connection
        if not hasattr(g, 'redis'):
            try:
                import redis
                redis_url = current_app.config.get('REDIS_URL', 'redis://localhost:6379/0')
                g.redis = redis.from_url(redis_url)
            except Exception as redis_err:
                current_app.logger.error(f"Error connecting to Redis: {str(redis_err)}")
                return None
        
        return g.redis
    except Exception as e:
        if has_app_context():
            current_app.logger.error(f"Error getting Redis client: {str(e)}")
        return None

# Custom JSON encoder to handle datetime and date objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)

# Role-based access control decorator
def roles_required(*roles):
    """Decorator to protect a route based on user roles.
    Also treats 'user' role as equivalent to 'student' role."""
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            
            # Check if user has one of the required roles
            if 'roles' not in claims:
                return jsonify({'message': 'Insufficient privileges'}), 403
            
            has_role = False
            for required_role in roles:
                for user_role in claims['roles']:
                    # Treat 'user' as equivalent to 'student'
                    if user_role == required_role or (required_role == 'student' and user_role == 'user'):
                        has_role = True
                        break
                if has_role:
                    break
                    
            if not has_role:
                return jsonify({'message': 'Insufficient privileges'}), 403
                
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Add a helper function to check if caching is enabled
def is_caching_enabled():
    """Check if caching is enabled in the application
    
    Returns:
        bool: True if caching is enabled, False otherwise
    """
    try:
        # Check if cache extension is configured
        if hasattr(current_app, 'extensions') and 'cache' in current_app.extensions:
            return True
        
        # As a fallback, check if redis is available
        r = get_redis_client()
        if r:
            try:
                # Simple connection test
                r.ping()
                return True
            except:
                return False
        
        return False
    except Exception as e:
        current_app.logger.warning(f"Error checking if caching is enabled: {str(e)}")
        return False

# Cache functions
def cache_data(key, data, timeout=300):
    """Cache data with the given key and timeout
    
    Returns:
        bool: True if caching was successful, False otherwise
    """
    from flask import current_app, has_app_context
    
    # Check if we have an application context
    if not has_app_context():
        return False
    
    # Check if caching is enabled
    if not is_caching_enabled():
        current_app.logger.warning(f"Caching is not enabled, data for {key} not cached")
        return False
        
    if not hasattr(current_app, 'extensions') or 'cache' not in current_app.extensions:
        current_app.logger.warning(f"Cache extension is not initialized, data for {key} not cached")
        return False
        
    cache = current_app.extensions.get('cache')
    if cache:
        try:
            if data is None and timeout == 0:
                # This is an invalidation request - delete key and related keys
                current_app.logger.info(f"Invalidating cache for {key}")
                
                # Delete specified key
                cache.delete(key)
                
                # For invalidating subject list cache, also invalidate global endpoints
                if key == 'all_subjects':
                    # Force cache clear for main endpoints
                    current_app.logger.info("Clearing all application caches due to subject change")
                    success = cache.clear()
                    current_app.logger.info(f"Cache clear {'successful' if success else 'failed'}")
                
                return True
            else:
                # Normal cache set operation
                # First, try to serialize complex objects before caching
                if isinstance(data, dict):
                    # Try to serialize any non-basic types in the dict
                    try:
                        serialized_data = data.copy()
                        for k, v in serialized_data.items():
                            if isinstance(v, (datetime, date)):
                                serialized_data[k] = v.isoformat()
                        data = serialized_data
                    except Exception as serialize_err:
                        current_app.logger.warning(f"Error serializing cache data for {key}: {str(serialize_err)}")
                
                # Set cache with timeout and retry up to 3 times
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        # Handle the case where cache might be a dict (SimpleCache fallback)
                        if hasattr(cache, 'set'):
                            success = cache.set(key, data, timeout=timeout)
                        else:
                            # Fallback for SimpleCache which might be a dict
                            cache[key] = data
                            success = True
                        
                        # Verify the data was cached by retrieving it
                        if success:
                            # Handle the case where cache might be a dict
                            if hasattr(cache, 'get'):
                                verify_data = cache.get(key)
                            else:
                                verify_data = cache.get(key, None)
                                
                            if verify_data is not None:
                                current_app.logger.debug(f"Cached response for {key} (expires in {timeout}s) - attempt {attempt+1}")
                                return True
                            else:
                                current_app.logger.warning(f"Cache verification failed for {key} - attempt {attempt+1}")
                                # Continue to retry
                        else:
                            current_app.logger.warning(f"Failed to cache data for {key} - attempt {attempt+1}")
                    except Exception as retry_err:
                        current_app.logger.error(f"Cache error on attempt {attempt+1} for {key}: {str(retry_err)}")
                    
                    # Only sleep between retries, not after the last attempt
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(0.1)  # 100ms delay between retries
                
                # Try direct Redis approach as a last resort
                try:
                    r = get_redis_client()
                    if r:
                        # Convert data to JSON string if it's a complex object
                        if isinstance(data, (dict, list)):
                            json_data = json.dumps(data, cls=CustomJSONEncoder)
                            r.setex(f"quizmaster_{key}", timeout, json_data)
                        else:
                            r.setex(f"quizmaster_{key}", timeout, str(data))
                        current_app.logger.info(f"Cached data using direct Redis for {key}")
                        return True
                except Exception as redis_err:
                    current_app.logger.error(f"Direct Redis caching failed for {key}: {str(redis_err)}")
                
                # Last resort - store in memory
                try:
                    from flask import g
                    if not hasattr(g, '_memory_cache'):
                        g._memory_cache = {}
                    g._memory_cache[key] = {
                        'data': data,
                        'expires': time.time() + timeout
                    }
                    current_app.logger.info(f"Cached data in memory for {key} (fallback)")
                    return True
                except Exception as memory_err:
                    current_app.logger.error(f"Memory caching failed for {key}: {str(memory_err)}")
                
                current_app.logger.error(f"All caching attempts failed for {key}")
                return False
        except Exception as e:
            current_app.logger.error(f"Cache error for key {key}: {str(e)}")
            return False
    else:
        current_app.logger.warning(f"Cache extension is not initialized, data for {key} not cached")
        return False

def get_cached_data(key):
    """Retrieve cached data for the given key
    
    Returns:
        data: The cached data or None if not found
    """
    from flask import current_app, g, has_app_context
    
    # Check if we have an application context
    if not has_app_context():
        return None
    
    # Check if caching is enabled
    if not is_caching_enabled():
        current_app.logger.warning(f"Caching is not enabled, cannot retrieve data for {key}")
        return None
    
    # Try with multiple approaches to ensure robust cache retrieval
    data = None
    error_message = None
    
    # First try with Flask-Caching extension
    try:
        if hasattr(current_app, 'extensions') and 'cache' in current_app.extensions:
            cache = current_app.extensions['cache']
            
            # Handle the case where cache might be a dict
            if hasattr(cache, 'get'):
                data = cache.get(key)
            else:
                data = cache.get(key, None)
                
            if data is not None:
                current_app.logger.debug(f"Cache hit for {key} using Flask-Caching")
                return data
            else:
                current_app.logger.debug(f"Cache miss for {key} using Flask-Caching")
    except Exception as cache_err:
        error_message = f"Flask-Caching error: {str(cache_err)}"
        current_app.logger.error(f"Error retrieving from Flask-Caching for {key}: {str(cache_err)}")
    
    # If Flask-Caching failed, try direct Redis approach
    if data is None:
        try:
            r = get_redis_client()
            if r:
                # Try with the key prefix that Flask-Caching might use
                for prefix in ['quizmaster_', '']:
                    try:
                        redis_data = r.get(f"{prefix}{key}")
                        if redis_data:
                            # Try to deserialize as JSON
                            try:
                                data = json.loads(redis_data)
                                current_app.logger.debug(f"Cache hit for {key} using direct Redis (JSON)")
                                return data
                            except json.JSONDecodeError:
                                # If not valid JSON, return as string
                                data = redis_data.decode('utf-8')
                                current_app.logger.debug(f"Cache hit for {key} using direct Redis (string)")
                                return data
                    except Exception as key_err:
                        current_app.logger.debug(f"Error retrieving {prefix}{key} from Redis: {str(key_err)}")
        except Exception as redis_err:
            error_message = f"{error_message}, Redis error: {str(redis_err)}" if error_message else f"Redis error: {str(redis_err)}"
            current_app.logger.error(f"Error with direct Redis access for {key}: {str(redis_err)}")
    
    # Finally, try memory cache as last resort
    if data is None:
        try:
            if hasattr(g, '_memory_cache') and key in g._memory_cache:
                cache_entry = g._memory_cache[key]
                # Check if expired
                if cache_entry['expires'] > time.time():
                    data = cache_entry['data']
                    current_app.logger.debug(f"Cache hit for {key} using memory cache")
                    return data
                else:
                    # Remove expired entry
                    del g._memory_cache[key]
                    current_app.logger.debug(f"Expired entry removed from memory cache for {key}")
        except Exception as memory_err:
            error_message = f"{error_message}, Memory cache error: {str(memory_err)}" if error_message else f"Memory cache error: {str(memory_err)}"
            current_app.logger.error(f"Error retrieving from memory cache for {key}: {str(memory_err)}")
    
    # If we got here, the data wasn't found
    if error_message:
        current_app.logger.warning(f"Cache retrieval errors for {key}: {error_message}")
    else:
        current_app.logger.debug(f"Cache miss for {key} (all methods)")
    
    return None

# JWT Helper functions
def verify_jwt(token):
    try:
        from flask_jwt_extended import decode_token as jwt_decode_token
        payload = jwt_decode_token(token)
        return payload
    except Exception as e:
        current_app.logger.error(f"JWT verification error: {str(e)}")
        return None

# For backward compatibility with old code
def verify_custom_token(token):
    if not token:
        return None
    try:
        # First try JWT format
        from flask_jwt_extended import decode_token as jwt_decode_token
        try:
            payload = jwt_decode_token(token)
            from backend.models import User
            user_id = payload.get('sub')
            if user_id:
                return User.query.get(int(user_id))
        except Exception:
            # If JWT fails, try legacy format
            pass
            
        # Try to decode as custom token (if applicable)
        # This depends on your implementation of decode_token
        payload = parse_token(token)
        from backend.models import User
        user_id = payload.get('id')
        if user_id:
            return User.query.get(int(user_id))
        return None
    except Exception as e:
        current_app.logger.error(f"Token verification error: {str(e)}")
        return None

# Fix decode_token if it doesn't exist - RENAMED to avoid duplicate function error
def parse_token(token):
    """Decode a token (for backward compatibility)"""
    if not token:
        return None
    
    try:
        from flask_jwt_extended import decode_token as jwt_decode
        return jwt_decode(token)
    except Exception as e:
        current_app.logger.error(f"Token decode error: {str(e)}")
        return {"error": str(e)}

import csv
from io import StringIO, BytesIO
from flask import render_template

# Add the flag at module level
WEASYPRINT_AVAILABLE = False

from backend.models import User, Score, Quiz

def calculate_quiz_stats(user_id):
    """Calculate user's quiz statistics"""
    scores = Score.query.filter_by(user_id=user_id).all()
    
    stats = {
        'total_quizzes': len(scores),
        'average_score': sum(s.total_scored for s in scores) / len(scores) if scores else 0,
        'best_subject': None,
        'recent_attempts': []
    }
    
    # Calculate best subject
    subject_scores = {}
    for score in scores:
        subject_name = score.quiz.chapter.subject.name
        if subject_name not in subject_scores:
            subject_scores[subject_name] = []
        subject_scores[subject_name].append(score.percentage)
    
    if subject_scores:
        avg_scores = {subject: sum(scores) / len(scores) for subject, scores in subject_scores.items()}
        stats['best_subject'] = max(avg_scores.items(), key=lambda x: x[1])[0]
    
    # Get recent attempts
    recent_scores = Score.query.filter_by(user_id=user_id).order_by(Score.timestamp.desc()).limit(5).all()
    for score in recent_scores:
        stats['recent_attempts'].append({
            'quiz_id': score.quiz_id,
            'subject': score.quiz.chapter.subject.name,
            'chapter': score.quiz.chapter.name,
            'date': score.timestamp,
            'score': score.total_scored,
            'total': score.total_questions,
            'percentage': score.percentage
        })
    
    return stats

@cache.memoize(timeout=3600)
def export_scores_csv(scores):
    """Export scores to CSV format"""
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Quiz', 'Chapter', 'Subject', 'Date', 'Score', 'Total', 'Percentage'])
    
    # Write data
    for score in scores:
        writer.writerow([
            f"Quiz {score.quiz_id}",
            score.quiz.chapter.name,
            score.quiz.chapter.subject.name,
            score.timestamp.strftime("%Y-%m-%d %H:%M"),
            score.total_scored,
            score.total_questions,
            f"{score.percentage}%"
        ])
    
    return output.getvalue()

def generate_report_html(user, scores):
    """Generate HTML content for monthly report"""
    stats = calculate_quiz_stats(user.id)
    return render_template(
        'report.html',
        user=user,
        scores=scores,
        stats=stats,
        date=datetime.utcnow().strftime("%B %Y")
    )

def generate_pdf(html_content):
    """Generate PDF from HTML content - fallback to HTML when WeasyPrint unavailable"""
    # Just return HTML content as PDF is not critical for functionality
    pdf_file = BytesIO(html_content.encode('utf-8'))
    pdf_file.seek(0)
    current_app.logger.warning("WeasyPrint not available - returning HTML instead of PDF")
    return pdf_file

def send_email(to, subject, html_content, attachment=None):
    """Send email with optional attachment"""
    try:
        # Import only if needed, to avoid circular imports
        from flask_mail import Message
        
        # Check if mail extension is configured
        if not hasattr(current_app, 'extensions') or 'mail' not in current_app.extensions:
            current_app.logger.error("Mail extension not configured")
            return False
            
        mail = current_app.extensions['mail']
        
        msg = Message(subject, recipients=[to])
        msg.html = html_content
        
        if attachment:
            msg.attach(
                filename=attachment.get('filename', 'attachment.pdf'),
                content_type=attachment.get('content_type', 'application/pdf'),
                data=attachment.get('data')
            )
        
        mail.send(msg)
        return True
    except ImportError:
        current_app.logger.error("Flask-Mail not installed")
        return False
    except Exception as e:
        current_app.logger.error(f"Email sending error: {str(e)}")
        return False

# Add this to your utilities
def verify_password(user, password):
    """Verify a user's password"""
    if user is None:
        return False
    return user.check_password(password)

# Add these missing functions that are imported in api.py
def validate_request(schema, request_data):
    """Validate request data against a schema"""
    try:
        return schema.load(request_data)
    except Exception as e:
        return {'errors': str(e)}, False

def safe_commit():
    """Safely commit changes to the database"""
    from .models import db
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database commit error: {str(e)}")
        return False

def rate_limit(limit, per):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simplified implementation - would use Redis in production
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def cached_endpoint(timeout=300):
    """Cache a view function's response using memoize"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if caching is enabled
            if not is_caching_enabled():
                return f(*args, **kwargs)
            
            # Use the memoize decorator from cache directly
            @cache.memoize(timeout=timeout)
            def cached_func(*func_args, **func_kwargs):
                return f(*func_args, **func_kwargs)
            
            # Call the memoized function with the same arguments
            return cached_func(*args, **kwargs)
        return decorated_function
    return decorator

# =============================================
# Report Management Using Redis
# =============================================

def get_redis_connection():
    """Get a Redis connection for report management"""
    from flask import current_app
    import redis
    
    redis_url = current_app.config.get('REDIS_URL', 'redis://localhost:6379/0')
    return redis.from_url(redis_url)

def create_report(report_data):
    """
    Create a new report entry in Redis
    
    Args:
        report_data (dict): Report metadata including:
            - user_id: ID of the user who requested the report
            - report_type: Type of report (user_activity, quiz_performance, etc.)
            - name: Human-readable name of the report
            - filters: Dictionary of filters applied
            
    Returns:
        str: Report ID
    """
    try:
        r = get_redis_connection()
        
        # Generate a unique ID
        report_id = str(uuid.uuid4())
        
        # Add timestamps
        report_data['created_at'] = datetime.now().isoformat()
        report_data['updated_at'] = datetime.now().isoformat()
        report_data['status'] = 'pending'  # pending, processing, completed, failed
        
        # Store in Redis
        r.set(f"report:{report_id}", json.dumps(report_data, cls=CustomJSONEncoder))
        
        # Add to the user's reports list
        if 'user_id' in report_data:
            r.lpush(f"user:{report_data['user_id']}:reports", report_id)
        
        # Add to the global reports list
        r.lpush("all_reports", report_id)
        
        return report_id
    except Exception as e:
        current_app.logger.error(f"Error creating report: {str(e)}")
        return None

def update_report_status(report_id, status, result=None):
    """
    Update the status of a report
    
    Args:
        report_id (str): Report ID
        status (str): New status (pending, processing, completed, failed)
        result (dict, optional): Result data for completed reports
        
    Returns:
        bool: Success or failure
    """
    try:
        r = get_redis_connection()
        
        # Get existing report data
        report_data_json = r.get(f"report:{report_id}")
        if not report_data_json:
            return False
            
        report_data = json.loads(report_data_json)
        
        # Update status and timestamp
        report_data['status'] = status
        report_data['updated_at'] = datetime.now().isoformat()
        
        # Add result data for completed reports
        if result:
            report_data['result'] = result
            
        # Save back to Redis
        r.set(f"report:{report_id}", json.dumps(report_data, cls=CustomJSONEncoder))
        
        return True
    except Exception as e:
        current_app.logger.error(f"Error updating report status: {str(e)}")
        return False

def get_report(report_id):
    """
    Get a report by ID
    
    Args:
        report_id (str): Report ID
        
    Returns:
        dict: Report data or None if not found
    """
    try:
        r = get_redis_connection()
        report_data_json = r.get(f"report:{report_id}")
        return json.loads(report_data_json) if report_data_json else None
    except Exception as e:
        current_app.logger.error(f"Error getting report: {str(e)}")
        return None

def get_user_reports(user_id, limit=20):
    """
    Get all reports for a user
    
    Args:
        user_id (int): User ID
        limit (int): Maximum number of reports to return
        
    Returns:
        list: List of report data dictionaries
    """
    try:
        r = get_redis_connection()
        report_ids = r.lrange(f"user:{user_id}:reports", 0, limit - 1)
        
        reports = []
        for report_id in report_ids:
            report_data = get_report(report_id.decode('utf-8'))
            if report_data:
                reports.append(report_data)
                
        return reports
    except Exception as e:
        current_app.logger.error(f"Error getting user reports: {str(e)}")
        return []

def get_all_reports(limit=50):
    """
    Get all reports (admin only)
    
    Args:
        limit (int): Maximum number of reports to return
        
    Returns:
        list: List of report data dictionaries
    """
    try:
        r = get_redis_connection()
        report_ids = r.lrange("all_reports", 0, limit - 1)
        
        reports = []
        for report_id in report_ids:
            report_data = get_report(report_id.decode('utf-8'))
            if report_data:
                reports.append(report_data)
                
        return reports
    except Exception as e:
        current_app.logger.error(f"Error getting all reports: {str(e)}")
        return []

def delete_report(report_id):
    """
    Delete a report
    
    Args:
        report_id (str): Report ID
        
    Returns:
        bool: Success or failure
    """
    try:
        r = get_redis_connection()
        
        # Get the report data to find the user_id
        report_data_json = r.get(f"report:{report_id}")
        if report_data_json:
            report_data = json.loads(report_data_json)
            
            # Remove from user's reports list if user_id exists
            if 'user_id' in report_data:
                r.lrem(f"user:{report_data['user_id']}:reports", 0, report_id)
        
        # Remove from global reports list
        r.lrem("all_reports", 0, report_id)
        
        # Delete the report data
        r.delete(f"report:{report_id}")
        
        return True
    except Exception as e:
        current_app.logger.error(f"Error deleting report: {str(e)}")
        return False


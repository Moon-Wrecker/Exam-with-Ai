import os
from celery import Celery
from datetime import datetime

def make_celery(app_name=__name__):
    """
    Create a new Celery app instance
    """
    from backend.config import Config

    # Use consistent configuration style with new-style config keys
    celery = Celery(
        app_name,
        broker=os.environ.get('CELERY_BROKER_URL', Config.REDIS_URL),
        backend=os.environ.get('CELERY_RESULT_BACKEND', Config.REDIS_URL),
    )
    
    # Configure Celery with new-style config keys
    celery.conf.update(
        task_serializer='json',
        result_serializer='json',
        accept_content=['json'],
        timezone='UTC',
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 minutes
        broker_connection_max_retries=5,
        broker_connection_retry=True, 
        broker_connection_retry_on_startup=True,
    )
    
    # This ensures all tasks are registered properly - use a list to be explicit
    celery.autodiscover_tasks(['backend', 'backend.tasks'])
    
    return celery

# Create the Celery app
celery_app = make_celery()

# Define task directly here to avoid circular imports
@celery_app.task(name='backend.tasks.test_celery')
def test_celery():
    """Simple task to verify Celery is working properly."""
    print("Running test_celery task")
    try:
        return {
            "status": "success",
            "message": "Celery is working correctly!",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        print(f"Error in test_celery task: {str(e)}")
        return {
            "status": "error",
            "message": f"Error in test task: {str(e)}"
        }

# Import report task functions to ensure they are registered
try:
    from backend.tasks import (
        generate_user_activity_report_func,
        generate_quiz_performance_report_func,
        generate_subject_analytics_report_func,
        generate_monthly_summary_report_func
    )
except ImportError:
    print("Warning: Could not import report generation tasks")

# Re-export the tasks so they can be found
if __name__ != '__main__':
    __all__ = ['celery_app', 'test_celery'] 
#!/usr/bin/env python
"""
Test script for Celery tasks.

This script can be used to directly test Celery tasks without using the web interface.
Run it with: python test_celery.py
"""

# Import the celery app directly from the new module 
from backend.celery_app import celery_app, test_celery
import time

if __name__ == "__main__":
    print("Testing Celery connection...")
    
    # Make sure all tasks are registered
    print(f"Registered tasks: {list(celery_app.tasks.keys())}")
    
    # Clear any existing tasks in the queue
    try:
        celery_app.control.purge()
        print("Cleared existing tasks from queue")
    except Exception as e:
        print(f"Warning: Could not clear tasks: {e}")
    
    time.sleep(1)
    
    # Run the test task
    print("Submitting test_celery task...")
    result = test_celery.delay()
    print(f"Task submitted with ID: {result.id}")
    print("Waiting for result...")
    
    # Wait for the task to complete
    try:
        task_result = result.get(timeout=10)  # Longer timeout for reliability
        print(f"Task completed with result: {task_result}")
        print("Celery is working correctly!")
    except Exception as e:
        print(f"Error waiting for task result: {str(e)}")
        print("Celery task execution failed!") 
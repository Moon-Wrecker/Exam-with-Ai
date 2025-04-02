#!/bin/bash

# Start services script for QuizMaster
echo "Starting QuizMaster Services..."

# Kill any existing processes
echo "Stopping existing processes..."
pkill -f "python app.py" || true
pkill -f "celery -A backend" || true
sleep 2
echo "Existing processes stopped."

# Check for Redis
echo "Checking Redis status..."
redis-cli ping > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Redis is not running. Starting Redis..."
    sudo service redis-server start
    sleep 2
    
    # Verify Redis started
    redis-cli ping > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to start Redis. Please start it manually with: sudo service redis-server start"
        exit 1
    fi
    echo "Redis started successfully."
else
    echo "Redis is already running."
fi

# Clear Redis if requested
if [ "$1" == "--clear-redis" ]; then
    echo "Clearing Redis database..."
    redis-cli flushall
    echo "Redis database cleared."
fi

# Start Celery Worker (in background)
echo "Starting Celery worker..."
cd "$(dirname "$0")"
celery -A backend.celery_app worker --loglevel=info > celery_worker.log 2>&1 &
WORKER_PID=$!
echo "Celery worker started with PID: $WORKER_PID"

# Start Celery Beat (in background)
echo "Starting Celery beat..."
celery -A backend.celery_app beat --loglevel=info > celery_beat.log 2>&1 &
BEAT_PID=$!
echo "Celery beat started with PID: $BEAT_PID"

# Wait for Celery to initialize
sleep 3

# Start Flask app
echo "Starting Flask application..."
python app.py

# This will only execute when Flask app is stopped
echo "Flask application stopped. Shutting down Celery processes..."
kill $WORKER_PID $BEAT_PID

echo "All services stopped." 
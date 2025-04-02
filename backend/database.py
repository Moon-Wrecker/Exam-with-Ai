from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool
import time
import logging

# Configure SQLAlchemy with optimized connection pooling
db = SQLAlchemy(engine_options={
    # Connection pooling settings
    'poolclass': QueuePool,
    'pool_size': 10,  # Maximum number of connections to keep in the pool
    'pool_timeout': 30,  # Seconds to wait before giving up on getting a connection
    'pool_recycle': 3600,  # Recycle connections every hour to avoid staleness
    'max_overflow': 5,  # Maximum number of connections to allow in addition to pool_size
})

# Set up SQL statement timing for performance monitoring in debug mode
@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    context._query_start_time = time.time()
    
@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    query_duration = time.time() - context._query_start_time
    # Log slow queries (over 0.5 seconds)
    if query_duration > 0.5:
        logging.warning(f"Slow query detected ({query_duration:.2f}s): {statement}")

# Function to check database health
def check_db_connection():
    """Check database connection health"""
    try:
        # A simple query that should always work
        db.session.execute("SELECT 1").scalar()
        return True
    except Exception as e:
        logging.error(f"Database connection error: {str(e)}")
        return False
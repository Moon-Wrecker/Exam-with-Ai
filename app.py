# quiz_master/app.py
import click
from flask import current_app, request
from flask.cli import with_appcontext
from backend import create_app, db
# Import only the models we need without user_datastore which causes circular imports
from backend.models import Role, User, Subject, Chapter, Quiz, Question, Score
from backend.config import Config
import os
from dotenv import load_dotenv
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from sqlalchemy import text

load_dotenv()  # This loads environment variables from .env

app = create_app()

# Add middleware to log all responses
@app.after_request
def log_response(response):
    """Log all API responses for debugging"""
    # Removing this debug logging since it's already handled by the backend/__init__.py
    # if app.debug and request.path.startswith('/api/'):
    #     app.logger.debug(f"Response: {request.method} {request.path} {response.status}")
    #     if response.is_json:
    #         app.logger.debug(f"Response JSON: {response.get_json()}")
    return response

# Configure CORS properly for token authentication
CORS(app, 
     resources={r"/api/*": {"origins": "*"}},
     supports_credentials=True, 
     expose_headers=['Content-Type', 'Authorization'],
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

with app.app_context():
    # Create database tables if they don't exist yet
    db.create_all()
    print("Database automatically initialized.")

    # Add time_taken column migration
    try:
        # Check if time_taken column exists
        try:
            db.session.query(Score.time_taken).first()
            print("Column 'time_taken' already exists in scores table.")
        except Exception as e:
            if 'no such column' in str(e).lower():
                # Column doesn't exist, add it
                print("Adding 'time_taken' column to scores table...")
                with db.engine.connect() as connection:
                    connection.execute(text('ALTER TABLE scores ADD COLUMN time_taken INTEGER'))
                    connection.commit()
                print("Column added successfully!")
            else:
                print(f"Error checking column: {e}")
    except Exception as migration_error:
        print(f"Migration error: {migration_error}")

    # Create admin role if it doesn't exist
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin', description='Administrator')
        db.session.add(admin_role)
        db.session.commit()
        print("Admin role created.")

    # Create student role if it doesn't exist
    student_role = Role.query.filter_by(name='student').first()
    if not student_role:
        student_role = Role(name='student', description='Student')
        db.session.add(student_role)
        db.session.commit()
        print("Student role created.")
    
    # Check if 'user' role exists and update any users with this role to have 'student' role instead
    user_role = Role.query.filter_by(name='user').first()
    if user_role:
        # Find all users with 'user' role
        for user in User.query.all():
            if user_role in user.roles and student_role not in user.roles:
                # Add student role to these users
                user.roles.append(student_role)
        # Don't delete the user role to avoid breaking existing logic
        print("Users with 'user' role have been given 'student' role for compatibility.")
        db.session.commit()

    # Create admin user if it doesn't exist
    admin_email = app.config.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = app.config.get('ADMIN_PASSWORD', 'admin123')
    
    admin_user = User.query.filter_by(email=admin_email).first()
    if not admin_user:
        admin_user = User(
            email=admin_email,
            full_name="Admin User",
            active=True
        )
        admin_user.set_password(admin_password)
        admin_user.roles = [admin_role]
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user created with email: {admin_email}")
    else:
        print("Admin user already exists.")

@app.cli.command("init-db")
@with_appcontext
def init_db():
    """Initialize the database."""
    db.create_all()
    click.echo("Database initialized.")

@app.cli.command("create-admin")
@with_appcontext
def create_admin():
    """Create an admin user."""
    admin_email = current_app.config.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = current_app.config.get('ADMIN_PASSWORD', 'admin123')
    
    if not User.query.filter_by(email=admin_email).first():
        # Create admin role if it doesn't exist
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator')
            db.session.add(admin_role)
            db.session.commit()
        
        # Create admin user
        admin_user = User(
            email=admin_email,
            full_name="Admin User",
            active=True
        )
        admin_user.set_password(admin_password)
        admin_user.roles = [admin_role]
        db.session.add(admin_user)
        db.session.commit()
        click.echo(f"Admin user created with email: {admin_email}")
    else:
        click.echo("Admin user already exists.")

@app.cli.command("migrate")
@with_appcontext
def run_migrations():
    """Run database migrations."""
    try:
        # Check if time_taken column exists
        try:
            db.session.query(Score.time_taken).first()
            click.echo("Column 'time_taken' already exists in scores table.")
        except Exception as e:
            if 'no such column' in str(e).lower():
                # Column doesn't exist, add it
                click.echo("Adding 'time_taken' column to scores table...")
                with db.engine.connect() as connection:
                    connection.execute(text('ALTER TABLE scores ADD COLUMN time_taken INTEGER'))
                    connection.commit()
                click.echo("Column added successfully!")
            else:
                click.echo(f"Error checking column: {e}")
    except Exception as migration_error:
        click.echo(f"Migration error: {migration_error}")

# Configure and initialize Celery if needed
from backend.tasks import init_celery
celery = init_celery(app)

# Add configuration for export directory
app.config['EXPORT_FOLDER'] = os.path.join(app.instance_path, 'exports')
# Create the directory if it doesn't exist
os.makedirs(app.config['EXPORT_FOLDER'], exist_ok=True)

if __name__ == "__main__":
    app.run(debug=True, port=1406)
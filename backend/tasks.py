import os
import csv
import io
from datetime import datetime, timedelta
from celery import Task
from flask import current_app, render_template
from flask_mail import Message, Mail
from sqlalchemy import func
import pandas as pd
import requests
import json

# Import models - do this before initializing Celery to avoid circular imports
from backend.models import db, User, Role, Subject, Chapter, Quiz, Question, Score

# Create a direct import of the Celery app to avoid circular imports
from backend.celery_app import celery_app as celery

# Import report utilities
from backend.utils import update_report_status

# Create a base task class that configures the app context
class FlaskTask(Task):
    abstract = True
    
    def __call__(self, *args, **kwargs):
        # Import the app factory function only when needed
        from backend import create_app
        
        # Using print for debugging as it doesn't require app context
        print(f"FlaskTask.__call__: Starting task {self.name}")
        
        try:
            app = create_app()
            print(f"FlaskTask.__call__: App created successfully for task {self.name}")
            
            with app.app_context():
                print(f"FlaskTask.__call__: Entered app context for task {self.name}")
                try:
                    result = self.run(*args, **kwargs)
                    print(f"FlaskTask.__call__: Task {self.name} completed successfully")
                    return result
                except Exception as e:
                    # Log the error within the app context
                    print(f"FlaskTask.__call__: Error in task {self.name}: {str(e)}")
                    app.logger.error(f"Error in {self.name}: {str(e)}")
                    # Re-raise the exception for Celery to handle it properly
                    raise
        except Exception as e:
            # Log exceptions that happen outside the app context
            print(f"FlaskTask.__call__: Failed to set up app context for {self.name}: {str(e)}")
            raise

# This function will be called to setup Celery with the real app
def init_celery(app=None):
    if app:
        # Convert old-style Celery config keys to new style
        config = {}
        for key, value in app.config.items():
            # Skip non-Celery config keys
            if not key.startswith('CELERY_'):
                continue
                
            # Convert key to new style
            new_key = key[7:].lower()
            config[new_key] = value
                
        # Update Celery with the new-style config
        celery.conf.update(config)
        
        # Use the FlaskTask base class for all tasks
        TaskBase = celery.Task
        class ContextTask(TaskBase):
            abstract = True
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return TaskBase.__call__(self, *args, **kwargs)
        celery.Task = ContextTask
    
    return celery

# Helper function to get task status
def get_task_status(task_id):
    """Get status of a task by its ID"""
    task = celery.AsyncResult(task_id)
    
    if not task:
        return None
    
    result = {
        'task_id': task_id,
        'status': task.status,
        'info': None
    }
    
    if task.status == 'SUCCESS':
        result['info'] = task.result
    elif task.status == 'FAILURE':
        result['info'] = str(task.info)
    
    return result

# Define task functions, we'll register them later

def export_user_scores_task_func(self, user_id):
    """Export user's quiz scores as CSV with improved error handling and retry logic"""
    
    try:
        # Get app logger from current_app which is now guaranteed to be within app context
        current_app.logger.info(f"Starting export task for user {user_id}")
        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found', 'status': 'failed'}
        
        # Get all scores for this user
        scores = Score.query.filter_by(user_id=user_id).all()
        
        if not scores:
            return {'error': 'No quiz scores found for this user', 'status': 'completed', 'message': 'No data to export'}
        
        # Generate CSV data
        csv_data = io.StringIO()
        csv_writer = csv.writer(csv_data)
        
        # Write header row
        header = ['Quiz ID', 'Quiz Date', 'Subject', 'Chapter', 'Score', 'Total Questions', 'Percentage', 'Date Taken']
        csv_writer.writerow(header)
        
        # Write score data
        for score in scores:
            quiz = score.quiz
            if not quiz:
                continue
                
            try:
                row = [
                    quiz.id,
                    quiz.date_of_quiz.strftime('%Y-%m-%d'),
                    quiz.chapter.subject.name,
                    quiz.chapter.name,
                    score.total_scored,
                    score.total_questions,
                    f"{score.percentage}%",
                    score.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                ]
                csv_writer.writerow(row)
            except Exception as inner_e:
                # Log error but continue processing other scores
                current_app.logger.error(f"Error processing score {score.id}: {str(inner_e)}")
                continue
        
        # Save CSV file
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"user_{user_id}_scores_{timestamp}.csv"
        filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
        
        # Ensure the export directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', newline='') as f:
            f.write(csv_data.getvalue())
        
        current_app.logger.info(f"Export completed for user {user_id}, file saved at {filepath}")
        
        # Send email notification
        try:
            email = user.email
            if email:
                from flask_mail import Mail
                mail = Mail(current_app)
                
                msg = Message("Your Quiz Scores Export is Ready",
                             recipients=[email])
                msg.body = f"Your requested quiz scores export is ready. Please download it from the application."
                mail.send(msg)
                current_app.logger.info(f"Notification email sent to {email}")
        except Exception as email_error:
            current_app.logger.error(f"Failed to send email notification: {str(email_error)}")
            # Don't retry just for email failure
        
        return {
            'filename': filename,
            'download_url': f"/reports/download/{filename}",
            'row_count': len(scores),
            'status': 'completed'
        }
        
    except Exception as e:
        # The error logging is now handled by FlaskTask.__call__
        # Retry the task if we haven't exceeded max retries
        try:
            self.retry(exc=e)
        except self.MaxRetriesExceededError:
            return {
                'error': str(e),
                'status': 'failed',
                'message': 'Export failed after multiple retry attempts'
            }
        
        return {'error': str(e), 'status': 'retrying'}

def export_users_data_task_func(self, admin_id, filters=None):
    """Export all users' data for admin"""
    
    try:
        admin = User.query.get(admin_id)
        if not admin:
            return {'error': 'Admin user not found'}
        
        # Check if the user is actually an admin
        is_admin = any(role.name == 'admin' for role in admin.roles)
        if not is_admin:
            return {'error': 'Only admins can export user data'}
        
        # Apply filters if provided
        query = User.query
        
        if filters:
            if 'role' in filters:
                query = query.join(User.roles).filter(Role.name == filters['role'])
            
            if 'active' in filters:
                query = query.filter(User.active == filters['active'])
        
        # Get all users
        users = query.all()
        
        if not users:
            return {'error': 'No users found matching the criteria'}
        
        # Generate CSV data
        csv_data = io.StringIO()
        csv_writer = csv.writer(csv_data)
        
        # Write header row
        header = ['ID', 'Email', 'Full Name', 'Qualification', 'Date of Birth', 
                  'Roles', 'Active', 'Quiz Attempts', 'Avg Score']
        csv_writer.writerow(header)
        
        # Write user data
        for user in users:
            # Get quiz statistics
            attempts = Score.query.filter_by(user_id=user.id).count()
            avg_score = db.session.query(func.avg(Score.percentage))\
                         .filter(Score.user_id == user.id)\
                         .scalar() or 0
            
            row = [
                user.id,
                user.email,
                user.full_name,
                user.qualification,
                user.dob.strftime('%Y-%m-%d') if user.dob else 'N/A',
                ', '.join(role.name for role in user.roles),
                'Yes' if user.active else 'No',
                attempts,
                f"{round(avg_score, 2)}%"
            ]
            csv_writer.writerow(row)
        
        # Save CSV file
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"admin_users_export_{timestamp}.csv"
        filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
        
        # Ensure the export directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', newline='') as f:
            f.write(csv_data.getvalue())
        
        # Send email notification
        email = admin.email
        if email:
            from flask_mail import Mail
            mail = Mail(current_app)
            
            msg = Message("User Data Export is Ready",
                         recipients=[email])
            msg.body = f"Your requested user data export is ready. Please download it from the admin dashboard."
            mail.send(msg)
        
        return {
            'filename': filename,
            'download_url': f"/reports/download/{filename}",
            'row_count': len(users)
        }
        
    except Exception as e:
        # Error logging is now handled by FlaskTask.__call__
        return {'error': str(e)}

def export_quiz_stats_task_func(self, admin_id, filters=None):
    """Export quiz statistics for admin users"""
    try:
        admin = User.query.get(admin_id)
        if not admin:
            return {'error': 'Admin user not found'}
        
        # Check if the user is actually an admin
        is_admin = any(role.name == 'admin' for role in admin.roles)
        if not is_admin:
            return {'error': 'Only admins can export quiz statistics'}
        
        # Build query based on filters
        query = Score.query
        
        if filters:
            if filters.get('subject_id'):
                query = query.join(Quiz).join(Chapter).filter(
                    Chapter.subject_id == filters['subject_id']
                )
            
            if filters.get('chapter_id'):
                query = query.join(Quiz).filter(
                    Quiz.chapter_id == filters['chapter_id']
                )
            
            if filters.get('quiz_id'):
                query = query.filter(Score.quiz_id == filters['quiz_id'])
            
            if filters.get('date_from'):
                from_date = datetime.strptime(filters['date_from'], '%Y-%m-%d')
                query = query.filter(Score.timestamp >= from_date)
            
            if filters.get('date_to'):
                to_date = datetime.strptime(filters['date_to'], '%Y-%m-%d')
                to_date = to_date.replace(hour=23, minute=59, second=59)
                query = query.filter(Score.timestamp <= to_date)
        
        # Execute query
        scores = query.all()
        
        if not scores:
            return {'error': 'No quiz scores found matching the criteria'}
        
        # Generate CSV data
        csv_data = io.StringIO()
        csv_writer = csv.writer(csv_data)
        
        # Write header row
        header = [
            'Quiz ID', 'User', 'Email', 'Subject', 'Chapter', 
            'Score', 'Total Questions', 'Percentage', 'Date Taken'
        ]
        csv_writer.writerow(header)
        
        # Write score data
        for score in scores:
            if not score.quiz or not score.user:
                continue
                
            row = [
                score.quiz_id,
                score.user.full_name or 'Unknown',
                score.user.email or 'Unknown',
                score.quiz.chapter.subject.name,
                score.quiz.chapter.name,
                score.total_scored,
                score.total_questions,
                f"{score.percentage}%",
                score.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ]
            csv_writer.writerow(row)
        
        # Save CSV file
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"quiz_stats_{timestamp}.csv"
        filepath = os.path.join(
            current_app.config.get('EXPORT_FOLDER', 'exports'), 
            filename
        )
        
        # Ensure the export directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', newline='') as f:
            f.write(csv_data.getvalue())
        
        # Send email notification
        if admin.email:
            mail = Mail(current_app)
            msg = Message(
                "Quiz Statistics Export is Ready",
                recipients=[admin.email]
            )
            msg.body = (
                "Your requested quiz statistics export is ready. "
                "Please download it from the admin dashboard."
            )
            mail.send(msg)
        
        return {
            'filename': filename,
            'download_url': f"/reports/download/{filename}",
            'row_count': len(scores)
        }
        
    except Exception as e:
        # Error logging is now handled by FlaskTask.__call__
        return {'error': str(e)}

def send_daily_reminders_func():
    """Send daily reminders to users who haven't visited or have new quizzes available.
    
    This task checks two conditions:
    1. If a user hasn't visited in the last 7 days
    2. If there are new quizzes created that are relevant to the user
    
    Sends reminders via Google Chat Webhook and email.
    """
    try:
        # Now current_app is guaranteed by FlaskTask.__call__ wrapper
        current_app.logger.info("Starting daily reminders task")
        
        # Get the webhook URL from config
        webhook_url = current_app.config.get('GOOGLE_CHAT_WEBHOOK_URL')
        
        # Get all active users
        users = User.query.filter_by(active=True).all()
        
        # Get date for 7 days ago to check inactivity
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        # Get recent quizzes (created in last 7 days)
        recent_quizzes = Quiz.query.filter(
            Quiz.date_of_quiz >= datetime.utcnow().date()
        ).all()
        
        # Map of subject IDs to names for quick lookup
        subject_info = {}
        
        # Track how many reminders we send
        reminders_sent = 0
        
        for user in users:
            should_send_reminder = False
            reminder_msg = f"Hello {user.full_name},\n\n"
            
            # Check last login date (if tracked)
            last_quiz_attempt = Score.query.filter_by(user_id=user.id).order_by(Score.timestamp.desc()).first()
            
            # Prepare reasons for notification
            reasons = []
            
            # Check if user hasn't attempted a quiz in 7 days
            if not last_quiz_attempt or last_quiz_attempt.timestamp < seven_days_ago:
                reasons.append("You haven't attempted any quizzes recently")
                should_send_reminder = True
            
            # Check if there are new quizzes relevant to the user
            relevant_quizzes = []
            for quiz in recent_quizzes:
                # Check if user already took this quiz
                already_taken = Score.query.filter_by(
                    user_id=user.id,
                    quiz_id=quiz.id
                ).first()
                
                if not already_taken:
                    # Get chapter and subject info
                    chapter = quiz.chapter
                    if chapter.subject_id not in subject_info:
                        subject_info[chapter.subject_id] = chapter.subject.name
                    
                    relevant_quizzes.append({
                        "quiz_id": quiz.id,
                        "chapter": chapter.name,
                        "subject": subject_info[chapter.subject_id],
                        "date": quiz.date_of_quiz.strftime("%Y-%m-%d")
                    })
            
            if relevant_quizzes:
                reasons.append(f"There are {len(relevant_quizzes)} new quizzes available for you")
                should_send_reminder = True
                
                # Add quiz details to the message
                reminder_msg += "New quizzes available:\n"
                for idx, quiz in enumerate(relevant_quizzes[:5], 1):  # Limit to 5 quizzes
                    reminder_msg += f"{idx}. {quiz['subject']} - {quiz['chapter']} (Date: {quiz['date']})\n"
                
                if len(relevant_quizzes) > 5:
                    reminder_msg += f"... and {len(relevant_quizzes) - 5} more.\n"
            
            if should_send_reminder:
                reminder_msg += "\nPlease log in to the Quiz Master platform to continue your learning journey!"
                
                # Send to Google Chat if webhook URL is configured
                if webhook_url:
                    try:
                        # Format message for Google Chat
                        chat_message = {
                            "text": f"📚 Quiz Reminder for {user.full_name} 📚\n\n" + reminder_msg
                        }
                        
                        # Send to Google Chat
                        response = requests.post(
                            webhook_url,
                            data=json.dumps(chat_message),
                            headers={'Content-Type': 'application/json'}
                        )
                        
                        if response.status_code == 200:
                            current_app.logger.info(f"Google Chat reminder sent to {user.email}")
                        else:
                            current_app.logger.warning(f"Failed to send Google Chat reminder: {response.status_code} - {response.text}")
                    
                    except Exception as chat_error:
                        current_app.logger.error(f"Error sending Google Chat notification: {str(chat_error)}")
                
                # Send email reminder
                if user.email:
                    try:
                        mail = Mail(current_app)
                        subject = "Quiz Master: New Quizzes Available & Activity Reminder"
                        
                        msg = Message(
                            subject=subject,
                            recipients=[user.email],
                            body=reminder_msg
                        )
                        
                        mail.send(msg)
                        current_app.logger.info(f"Email reminder sent to {user.email}")
                        reminders_sent += 1
                        
                    except Exception as email_error:
                        current_app.logger.error(f"Error sending email reminder: {str(email_error)}")
        
        return {
            "status": "success",
            "reminders_sent": reminders_sent,
            "message": f"Successfully sent {reminders_sent} reminders"
        }
    
    except Exception as e:
        # Error is already logged by FlaskTask.__call__
        return {
            "status": "error",
            "message": str(e)
        }

def send_monthly_reports_func(self):
    """Generate and send monthly activity reports to all users.
    
    The report includes:
    - Quiz details
    - Total quizzes taken in the month
    - Average score
    - Ranking compared to other users
    - Performance by subject
    
    This should run on the first day of each month.
    """
    try:
        current_app.logger.info("Starting monthly report generation task")
        
        # Get last month's date range
        today = datetime.now()
        first_day_of_this_month = today.replace(day=1)
        last_day_of_last_month = first_day_of_this_month - timedelta(days=1)
        first_day_of_last_month = last_day_of_last_month.replace(day=1)
        
        # Format month name for report
        month_name = first_day_of_last_month.strftime("%B %Y")
        
        # Get all active users
        users = User.query.filter_by(active=True).all()
        
        # Get all scores for last month to calculate rankings
        all_month_scores = Score.query.filter(
            Score.timestamp >= first_day_of_last_month,
            Score.timestamp <= last_day_of_last_month
        ).all()
        
        # Calculate average scores by user for ranking
        user_avg_scores = {}
        for score in all_month_scores:
            if score.user_id not in user_avg_scores:
                user_avg_scores[score.user_id] = {
                    'total': 0,
                    'count': 0,
                    'sum': 0
                }
            
            user_avg_scores[score.user_id]['sum'] += score.percentage
            user_avg_scores[score.user_id]['count'] += 1
        
        # Calculate averages
        for user_id in user_avg_scores:
            if user_avg_scores[user_id]['count'] > 0:
                user_avg_scores[user_id]['total'] = round(
                    user_avg_scores[user_id]['sum'] / user_avg_scores[user_id]['count'], 
                    2
                )
        
        # Sort by average score for ranking
        ranked_users = sorted(
            user_avg_scores.items(), 
            key=lambda x: x[1]['total'], 
            reverse=True
        )
        
        # Create a rank lookup dictionary
        user_ranks = {user_id: idx + 1 for idx, (user_id, _) in enumerate(ranked_users)}
        
        # Track successful report sends
        reports_sent = 0
        
        for user in users:
            try:
                # Get the user's scores from last month
                user_scores = Score.query.filter(
                    Score.user_id == user.id,
                    Score.timestamp >= first_day_of_last_month,
                    Score.timestamp <= last_day_of_last_month
                ).all()
                
                # Skip users with no activity last month
                if not user_scores:
                    current_app.logger.info(f"No monthly activity for user {user.email}, skipping report")
                    continue
                
                # Calculate user stats
                total_quizzes = len(user_scores)
                avg_score = sum(score.percentage for score in user_scores) / total_quizzes if total_quizzes > 0 else 0
                
                # Get user rank
                user_rank = user_ranks.get(user.id, "N/A")
                total_active_users = len(user_ranks)
                
                # Calculate performance by subject
                subject_performance = {}
                for score in user_scores:
                    quiz = score.quiz
                    if not quiz or not quiz.chapter or not quiz.chapter.subject:
                        continue
                        
                    subject_id = quiz.chapter.subject.id
                    subject_name = quiz.chapter.subject.name
                    
                    if subject_id not in subject_performance:
                        subject_performance[subject_id] = {
                            'name': subject_name,
                            'total': 0,
                            'count': 0,
                            'sum': 0
                        }
                    
                    subject_performance[subject_id]['sum'] += score.percentage
                    subject_performance[subject_id]['count'] += 1
                
                # Calculate average by subject
                for subject_id in subject_performance:
                    if subject_performance[subject_id]['count'] > 0:
                        subject_performance[subject_id]['total'] = round(
                            subject_performance[subject_id]['sum'] / subject_performance[subject_id]['count'],
                            2
                        )
                
                # Generate HTML report
                try:
                    html_report = render_template(
                        'monthly_report.html',  # Make sure this template exists
                        user=user,
                        month=month_name,
                        total_quizzes=total_quizzes,
                        avg_score=round(avg_score, 2),
                        rank=user_rank,
                        total_users=total_active_users,
                        subject_performance=subject_performance,
                        scores=user_scores[:10],  # Limit to 10 most recent scores
                        current_date=datetime.now().strftime('%Y-%m-%d')
                    )
                except Exception as template_error:
                    current_app.logger.error(f"Error rendering report template: {str(template_error)}")
                    # Fallback to plain text report
                    html_report = None
                
                # Create plain text version as fallback
                text_report = f"""Monthly Activity Report - {month_name}

Dear {user.full_name},

Here is your activity summary for {month_name}:

Total Quizzes Attempted: {total_quizzes}
Average Score: {round(avg_score, 2)}%
Your Rank: {user_rank} out of {total_active_users} active users

Subject Performance:
"""
                
                for subject in subject_performance.values():
                    text_report += f"- {subject['name']}: {subject['total']}% ({subject['count']} quizzes)\n"
                
                text_report += """
Keep up the good work! Regular practice leads to better results.

Quiz Master Team
"""
                
                # Send the email report
                if user.email:
                    try:
                        mail = Mail(current_app)
                        msg = Message(
                            subject=f"Quiz Master: Your {month_name} Activity Report",
                            recipients=[user.email]
                        )
                        
                        # Use HTML if available, otherwise use plain text
                        if html_report:
                            msg.html = html_report
                            msg.body = text_report  # Fallback
                        else:
                            msg.body = text_report
                        
                        mail.send(msg)
                        current_app.logger.info(f"Monthly report sent to {user.email}")
                        reports_sent += 1
                        
                    except Exception as email_error:
                        current_app.logger.error(f"Error sending monthly report email: {str(email_error)}")
            
            except Exception as user_error:
                current_app.logger.error(f"Error generating report for user {user.id}: {str(user_error)}")
                continue
        
        return {
            "status": "success",
            "reports_sent": reports_sent,
            "message": f"Successfully sent {reports_sent} monthly reports"
        }
    
    except Exception as e:
        # Error is already logged by FlaskTask.__call__
        # Retry the task
        try:
            self.retry(exc=e)
        except self.MaxRetriesExceededError:
            return {
                "status": "error",
                "message": f"Failed after multiple retries: {str(e)}"
            }

# Register all tasks with Celery
export_user_scores_task = celery.task(
    bind=True, 
    max_retries=3, 
    default_retry_delay=60
)(export_user_scores_task_func)

export_users_data_task = celery.task(
    bind=True
)(export_users_data_task_func)

export_quiz_stats_task = celery.task(
    bind=True
)(export_quiz_stats_task_func)

send_daily_reminders = celery.task(
    name='backend.tasks.send_daily_reminders'
)(send_daily_reminders_func)

send_monthly_reports = celery.task(
    bind=True,
    name='backend.tasks.send_monthly_reports',
    max_retries=3,
    default_retry_delay=120
)(send_monthly_reports_func)

# =============================================
# Report Generation Tasks
# =============================================

@celery.task(name='backend.tasks.generate_user_activity_report_func', bind=True, base=FlaskTask)
def generate_user_activity_report_func(self, report_id, admin_id, filters=None):
    """Generate a report on user activity"""
    try:
        # Update status to processing
        update_report_status(report_id, 'processing')
        
        current_app.logger.info(f"Starting user activity report generation for admin {admin_id}")
        
        # Verify admin permissions
        admin = User.query.get(admin_id)
        if not admin or not any(role.name == 'admin' for role in admin.roles):
            update_report_status(report_id, 'failed', {'error': 'Unauthorized access'})
            return {'error': 'Unauthorized access'}
        
        # Build query based on filters
        query = User.query
        
        if filters:
            if filters.get('user_filter') == 'active':
                query = query.filter(User.active == True)
            elif filters.get('user_filter') == 'inactive':
                query = query.filter(User.active == False)
            
            # Handle date range filtering for last login/activity
            if filters.get('start_date') and filters.get('end_date'):
                start_date = datetime.strptime(filters['start_date'], '%Y-%m-%d')
                end_date = datetime.strptime(filters['end_date'], '%Y-%m-%d')
                
                # Get users with activity in this date range
                user_ids = db.session.query(Score.user_id).filter(
                    Score.timestamp >= start_date,
                    Score.timestamp <= end_date
                ).distinct().all()
                
                user_ids = [uid[0] for uid in user_ids]
                query = query.filter(User.id.in_(user_ids))
        
        # Get users
        users = query.all()
        
        if not users:
            update_report_status(report_id, 'completed', {
                'message': 'No users found matching criteria',
                'row_count': 0
            })
            return {'message': 'No users found matching criteria'}
        
        # Prepare data for the report
        user_data = []
        for user in users:
            # Get user's activity stats
            scores = Score.query.filter_by(user_id=user.id).all()
            total_quizzes = len(scores)
            
            if total_quizzes > 0:
                avg_score = sum(score.percentage for score in scores) / total_quizzes
                last_activity = max(score.timestamp for score in scores).strftime('%Y-%m-%d')
            else:
                avg_score = 0
                last_activity = 'Never'
            
            user_data.append({
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'active': user.active,
                'total_quizzes': total_quizzes,
                'avg_score': round(avg_score, 2),
                'last_activity': last_activity,
                'roles': [role.name for role in user.roles]
            })
        
        # Generate the report file
        if filters.get('format', 'csv').lower() == 'csv':
            # CSV report
            csv_data = io.StringIO()
            csv_writer = csv.writer(csv_data)
            
            # Write header
            header = ['ID', 'Email', 'Full Name', 'Status', 'Quizzes Taken', 
                     'Average Score', 'Last Activity', 'Roles']
            csv_writer.writerow(header)
            
            # Write data rows
            for user in user_data:
                row = [
                    user['id'],
                    user['email'],
                    user['full_name'],
                    'Active' if user['active'] else 'Inactive',
                    user['total_quizzes'],
                    f"{user['avg_score']}%",
                    user['last_activity'],
                    ', '.join(user['roles'])
                ]
                csv_writer.writerow(row)
            
            # Save the file
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"user_activity_report_{timestamp}.csv"
            filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', newline='') as f:
                f.write(csv_data.getvalue())
                
            # Update report status
            update_report_status(report_id, 'completed', {
                'filename': filename,
                'download_url': f"/reports/download/{filename}",
                'format': 'csv',
                'row_count': len(users)
            })
            
            return {
                'status': 'completed',
                'filename': filename,
                'row_count': len(users)
            }
            
        elif filters.get('format', 'csv').lower() == 'pdf':
            # For PDF, we'll create a HTML report and then convert it
            try:
                from weasyprint import HTML
                
                # Generate HTML report
                html_content = render_template(
                    'user_activity_report.html',
                    title='User Activity Report',
                    users=user_data,
                    generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    filters=filters
                )
                
                # Generate PDF from HTML
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                filename = f"user_activity_report_{timestamp}.pdf"
                filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
                
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
                HTML(string=html_content).write_pdf(filepath)
                
                # Update report status
                update_report_status(report_id, 'completed', {
                    'filename': filename,
                    'download_url': f"/reports/download/{filename}",
                    'format': 'pdf',
                    'row_count': len(users)
                })
                
                return {
                    'status': 'completed',
                    'filename': filename,
                    'row_count': len(users)
                }
                
            except ImportError:
                # Fallback to HTML if weasyprint is not available
                current_app.logger.warning("WeasyPrint not available, falling back to HTML report")
                filters['format'] = 'html'
        
        if filters.get('format', 'csv').lower() == 'html':
            # HTML report
            html_content = render_template(
                'user_activity_report.html',
                title='User Activity Report',
                users=user_data,
                generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                filters=filters
            )
            
            # Save the file
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"user_activity_report_{timestamp}.html"
            filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                f.write(html_content)
            
            # Update report status
            update_report_status(report_id, 'completed', {
                'filename': filename,
                'download_url': f"/reports/download/{filename}",
                'format': 'html',
                'row_count': len(users)
            })
            
            return {
                'status': 'completed',
                'filename': filename,
                'row_count': len(users)
            }
        
    except Exception as e:
        current_app.logger.error(f"Error generating user activity report: {str(e)}")
        update_report_status(report_id, 'failed', {'error': str(e)})
        
        # Try to retry the task
        try:
            self.retry(exc=e, countdown=60, max_retries=3)
        except self.MaxRetriesExceededError:
            return {
                'error': str(e),
                'status': 'failed'
            }

@celery.task(name='backend.tasks.generate_quiz_performance_report_func', bind=True, base=FlaskTask)
def generate_quiz_performance_report_func(self, report_id, admin_id, filters=None):
    """Generate a report on quiz performance"""
    try:
        # Update status to processing
        update_report_status(report_id, 'processing')
        
        current_app.logger.info(f"Starting quiz performance report generation for admin {admin_id}")
        
        # Verify admin permissions
        admin = User.query.get(admin_id)
        if not admin or not any(role.name == 'admin' for role in admin.roles):
            update_report_status(report_id, 'failed', {'error': 'Unauthorized access'})
            return {'error': 'Unauthorized access'}
        
        # Build query based on filters
        query = Score.query.join(Quiz).join(Chapter)
        
        if filters:
            if filters.get('subject_id'):
                query = query.filter(Chapter.subject_id == filters['subject_id'])
            
            if filters.get('start_date') and filters.get('end_date'):
                start_date = datetime.strptime(filters['start_date'], '%Y-%m-%d')
                end_date = datetime.strptime(filters['end_date'], '%Y-%m-%d')
                query = query.filter(Score.timestamp >= start_date, Score.timestamp <= end_date)
        
        # Get scores
        scores = query.all()
        
        if not scores:
            update_report_status(report_id, 'completed', {
                'message': 'No quiz data found matching criteria',
                'row_count': 0
            })
            return {'message': 'No quiz data found matching criteria'}
        
        # Prepare data for the report
        quiz_data = []
        for score in scores:
            quiz = score.quiz
            user = score.user
            
            if not quiz or not user:
                continue
                
            quiz_data.append({
                'quiz_id': quiz.id,
                'user_id': user.id,
                'user_name': user.full_name,
                'user_email': user.email,
                'subject': quiz.chapter.subject.name,
                'chapter': quiz.chapter.name,
                'date_of_quiz': quiz.date_of_quiz.strftime('%Y-%m-%d'),
                'time_duration': quiz.time_duration,
                'score': score.total_scored,
                'total_questions': score.total_questions,
                'percentage': score.percentage,
                'attempt_date': score.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        # Generate the report file
        if filters.get('format', 'csv').lower() == 'csv':
            # CSV report
            csv_data = io.StringIO()
            csv_writer = csv.writer(csv_data)
            
            # Write header
            header = ['Quiz ID', 'User', 'Email', 'Subject', 'Chapter', 'Quiz Date', 
                     'Duration (min)', 'Score', 'Total Questions', 'Percentage', 'Attempt Date']
            csv_writer.writerow(header)
            
            # Write data rows
            for item in quiz_data:
                row = [
                    item['quiz_id'],
                    item['user_name'],
                    item['user_email'],
                    item['subject'],
                    item['chapter'],
                    item['date_of_quiz'],
                    item['time_duration'],
                    item['score'],
                    item['total_questions'],
                    f"{item['percentage']}%",
                    item['attempt_date']
                ]
                csv_writer.writerow(row)
            
            # Save the file
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"quiz_performance_report_{timestamp}.csv"
            filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', newline='') as f:
                f.write(csv_data.getvalue())
                
            # Update report status
            update_report_status(report_id, 'completed', {
                'filename': filename,
                'download_url': f"/reports/download/{filename}",
                'format': 'csv',
                'row_count': len(quiz_data)
            })
            
            return {
                'status': 'completed',
                'filename': filename,
                'row_count': len(quiz_data)
            }
            
        # Additional formats (PDF, HTML) would be implemented similarly to the user activity report
        
    except Exception as e:
        current_app.logger.error(f"Error generating quiz performance report: {str(e)}")
        update_report_status(report_id, 'failed', {'error': str(e)})
        
        # Try to retry the task
        try:
            self.retry(exc=e, countdown=60, max_retries=3)
        except self.MaxRetriesExceededError:
            return {
                'error': str(e),
                'status': 'failed'
            }

@celery.task(name='backend.tasks.generate_subject_analytics_report_func', bind=True, base=FlaskTask)
def generate_subject_analytics_report_func(self, report_id, admin_id, filters=None):
    """Generate a report on subject analytics"""
    try:
        # Update status to processing
        update_report_status(report_id, 'processing')
        
        current_app.logger.info(f"Starting subject analytics report generation for admin {admin_id}")
        
        # Verify admin permissions
        admin = User.query.get(admin_id)
        if not admin or not any(role.name == 'admin' for role in admin.roles):
            update_report_status(report_id, 'failed', {'error': 'Unauthorized access'})
            return {'error': 'Unauthorized access'}
        
        # Get all subjects or filter by subject ID
        subject_query = Subject.query
        if filters and filters.get('subject_id'):
            subject_query = subject_query.filter(Subject.id == filters['subject_id'])
        
        subjects = subject_query.all()
        
        if not subjects:
            update_report_status(report_id, 'completed', {
                'message': 'No subjects found matching criteria',
                'row_count': 0
            })
            return {'message': 'No subjects found matching criteria'}
        
        # Prepare data for the report - aggregate stats by subject
        subject_data = []
        
        for subject in subjects:
            # Get chapters for this subject
            chapters = Chapter.query.filter_by(subject_id=subject.id).all()
            total_chapters = len(chapters)
            
            # Get all quizzes for this subject
            quizzes = []
            for chapter in chapters:
                chapter_quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
                quizzes.extend(chapter_quizzes)
            
            total_quizzes = len(quizzes)
            
            # Get all scores for quizzes in this subject
            quiz_ids = [quiz.id for quiz in quizzes]
            
            score_query = Score.query.filter(Score.quiz_id.in_(quiz_ids))
            
            # Apply date filter if provided
            if filters and filters.get('start_date') and filters.get('end_date'):
                start_date = datetime.strptime(filters['start_date'], '%Y-%m-%d')
                end_date = datetime.strptime(filters['end_date'], '%Y-%m-%d')
                score_query = score_query.filter(Score.timestamp >= start_date, Score.timestamp <= end_date)
            
            scores = score_query.all()
            
            total_attempts = len(scores)
            avg_score = sum(score.percentage for score in scores) / total_attempts if total_attempts > 0 else 0
            
            # Calculate unique students
            unique_students = len(set(score.user_id for score in scores))
            
            # Calculate difficulty level (percentage of students scoring less than 60%)
            difficulty = len([score for score in scores if score.percentage < 60]) / total_attempts if total_attempts > 0 else 0
            
            subject_data.append({
                'subject_id': subject.id,
                'subject_name': subject.name,
                'total_chapters': total_chapters,
                'total_quizzes': total_quizzes,
                'total_attempts': total_attempts,
                'unique_students': unique_students,
                'avg_score': round(avg_score, 2),
                'difficulty_level': round(difficulty * 100, 2),
                'chapters': [{'id': chapter.id, 'name': chapter.name} for chapter in chapters]
            })
        
        # Generate the report file
        if filters.get('format', 'csv').lower() == 'csv':
            # CSV report
            csv_data = io.StringIO()
            csv_writer = csv.writer(csv_data)
            
            # Write header
            header = ['Subject ID', 'Subject Name', 'Total Chapters', 'Total Quizzes', 
                     'Total Attempts', 'Unique Students', 'Average Score', 'Difficulty Level']
            csv_writer.writerow(header)
            
            # Write data rows
            for item in subject_data:
                row = [
                    item['subject_id'],
                    item['subject_name'],
                    item['total_chapters'],
                    item['total_quizzes'],
                    item['total_attempts'],
                    item['unique_students'],
                    f"{item['avg_score']}%",
                    f"{item['difficulty_level']}%"
                ]
                csv_writer.writerow(row)
            
            # Save the file
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"subject_analytics_report_{timestamp}.csv"
            filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', newline='') as f:
                f.write(csv_data.getvalue())
                
            # Update report status
            update_report_status(report_id, 'completed', {
                'filename': filename,
                'download_url': f"/reports/download/{filename}",
                'format': 'csv',
                'row_count': len(subject_data)
            })
            
            return {
                'status': 'completed',
                'filename': filename,
                'row_count': len(subject_data)
            }
            
        # Additional formats (PDF, HTML) would be implemented similarly to the user activity report
        
    except Exception as e:
        current_app.logger.error(f"Error generating subject analytics report: {str(e)}")
        update_report_status(report_id, 'failed', {'error': str(e)})
        
        # Try to retry the task
        try:
            self.retry(exc=e, countdown=60, max_retries=3)
        except self.MaxRetriesExceededError:
            return {
                'error': str(e),
                'status': 'failed'
            }

@celery.task(name='backend.tasks.generate_monthly_summary_report_func', bind=True, base=FlaskTask)
def generate_monthly_summary_report_func(self, report_id, admin_id, filters=None):
    """Generate a monthly summary report"""
    try:
        # Update status to processing
        update_report_status(report_id, 'processing')
        
        current_app.logger.info(f"Starting monthly summary report generation for admin {admin_id}")
        
        # Verify admin permissions
        admin = User.query.get(admin_id)
        if not admin or not any(role.name == 'admin' for role in admin.roles):
            update_report_status(report_id, 'failed', {'error': 'Unauthorized access'})
            return {'error': 'Unauthorized access'}
        
        # Determine date range (default to last month if not specified)
        if filters and filters.get('start_date') and filters.get('end_date'):
            start_date = datetime.strptime(filters['start_date'], '%Y-%m-%d')
            end_date = datetime.strptime(filters['end_date'], '%Y-%m-%d')
        else:
            # Get last month's date range
            today = datetime.now()
            first_day_of_this_month = today.replace(day=1)
            last_day_of_last_month = first_day_of_this_month - timedelta(days=1)
            first_day_of_last_month = last_day_of_last_month.replace(day=1)
            
            start_date = first_day_of_last_month
            end_date = last_day_of_last_month
        
        # Format month name for report
        month_name = start_date.strftime("%B %Y")
        
        # Get all scores for the specified period
        scores = Score.query.filter(
            Score.timestamp >= start_date,
            Score.timestamp <= end_date
        ).all()
        
        if not scores:
            update_report_status(report_id, 'completed', {
                'message': 'No data found for the specified period',
                'row_count': 0
            })
            return {'message': 'No data found for the specified period'}
        
        # Calculate summary statistics
        total_attempts = len(scores)
        unique_users = len(set(score.user_id for score in scores))
        unique_quizzes = len(set(score.quiz_id for score in scores))
        avg_score = sum(score.percentage for score in scores) / total_attempts
        
        # Get count of new users registered in this period
        new_users = User.query.filter(
            User.confirmed_at >= start_date,
            User.confirmed_at <= end_date
        ).count()
        
        # Group scores by subject
        subject_performance = {}
        for score in scores:
            quiz = score.quiz
            if not quiz or not quiz.chapter or not quiz.chapter.subject:
                continue
                
            subject_id = quiz.chapter.subject.id
            subject_name = quiz.chapter.subject.name
            
            if subject_id not in subject_performance:
                subject_performance[subject_id] = {
                    'name': subject_name,
                    'total_attempts': 0,
                    'sum_score': 0,
                    'unique_users': set()
                }
            
            subject_performance[subject_id]['total_attempts'] += 1
            subject_performance[subject_id]['sum_score'] += score.percentage
            subject_performance[subject_id]['unique_users'].add(score.user_id)
        
        # Calculate averages
        for subject_id in subject_performance:
            attempts = subject_performance[subject_id]['total_attempts']
            if attempts > 0:
                subject_performance[subject_id]['avg_score'] = round(
                    subject_performance[subject_id]['sum_score'] / attempts, 2
                )
                subject_performance[subject_id]['unique_users'] = len(subject_performance[subject_id]['unique_users'])
        
        # Prepare the summary data
        summary_data = {
            'month_name': month_name,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'total_attempts': total_attempts,
            'unique_users': unique_users,
            'unique_quizzes': unique_quizzes,
            'new_users': new_users,
            'avg_score': round(avg_score, 2),
            'subject_performance': [
                {
                    'subject_id': subject_id,
                    'name': data['name'],
                    'total_attempts': data['total_attempts'],
                    'avg_score': data['avg_score'],
                    'unique_users': data['unique_users']
                }
                for subject_id, data in subject_performance.items()
            ]
        }
        
        # Generate the report file
        if filters.get('format', 'csv').lower() == 'csv':
            # CSV report
            csv_data = io.StringIO()
            csv_writer = csv.writer(csv_data)
            
            # Write main summary
            csv_writer.writerow(['Monthly Summary Report', month_name])
            csv_writer.writerow(['Start Date', start_date.strftime('%Y-%m-%d')])
            csv_writer.writerow(['End Date', end_date.strftime('%Y-%m-%d')])
            csv_writer.writerow([])
            csv_writer.writerow(['Key Metrics', 'Value'])
            csv_writer.writerow(['Total Quiz Attempts', total_attempts])
            csv_writer.writerow(['Unique Active Users', unique_users])
            csv_writer.writerow(['Unique Quizzes Taken', unique_quizzes])
            csv_writer.writerow(['New User Registrations', new_users])
            csv_writer.writerow(['Average Score', f"{round(avg_score, 2)}%"])
            csv_writer.writerow([])
            
            # Write subject performance
            csv_writer.writerow(['Subject Performance'])
            csv_writer.writerow(['Subject', 'Total Attempts', 'Average Score', 'Unique Users'])
            
            for subject in summary_data['subject_performance']:
                csv_writer.writerow([
                    subject['name'],
                    subject['total_attempts'],
                    f"{subject['avg_score']}%",
                    subject['unique_users']
                ])
            
            # Save the file
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"monthly_summary_report_{timestamp}.csv"
            filepath = os.path.join(current_app.config.get('EXPORT_FOLDER', 'exports'), filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', newline='') as f:
                f.write(csv_data.getvalue())
                
            # Update report status
            update_report_status(report_id, 'completed', {
                'filename': filename,
                'download_url': f"/reports/download/{filename}",
                'format': 'csv',
                'row_count': total_attempts,
                'month': month_name
            })
            
            return {
                'status': 'completed',
                'filename': filename,
                'row_count': total_attempts,
                'month': month_name
            }
            
        # Additional formats (PDF, HTML) would be implemented similarly to the user activity report
        
    except Exception as e:
        current_app.logger.error(f"Error generating monthly summary report: {str(e)}")
        update_report_status(report_id, 'failed', {'error': str(e)})
        
        # Try to retry the task
        try:
            self.retry(exc=e, countdown=60, max_retries=3)
        except self.MaxRetriesExceededError:
            return {
                'error': str(e),
                'status': 'failed'
            }
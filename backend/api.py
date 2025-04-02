from flask import Blueprint, request, jsonify, current_app, send_file, render_template
from flask_jwt_extended import (create_access_token, create_refresh_token,
                               jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request)
import uuid
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
from functools import wraps
import os
from backend import token_blocklist, cache
from backend.models import db, User, Role, Subject, Chapter, Quiz, Question, Score
from backend.utils import verify_password, get_cached_data, cache_data, validate_request, safe_commit, rate_limit, cached_endpoint, create_report, update_report_status, get_report, get_user_reports, get_all_reports, delete_report
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException
import json
from sqlalchemy import func
import time
import zipfile

# Create blueprint
blu = Blueprint('api', __name__, url_prefix='/api')

# Helper function to treat 'user' role as 'student'
def is_role_equivalent(user_role, required_role):
    """Checks if a user role is equivalent to the required role.
    Specifically, treats 'user' as equivalent to 'student'."""
    if user_role == required_role:
        return True
    if required_role == 'student' and user_role == 'user':
        return True
    return False

# Health check endpoint
@blu.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'message': 'Backend API is running'
    }), 200

# Test route for jobs
@blu.route('/jobs/test', methods=['GET'])
def jobs_test_page():
    """Render a test page for trying out the backend jobs"""
    return render_template('jobs_test.html')

# Define roles_required here since we're not importing it from models
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            
            # Check if user has one of the required roles
            # Also accept 'user' role if 'student' is required
            if 'roles' not in claims:
                return jsonify({'message': 'Insufficient privileges'}), 403
            
            has_role = False
            for required_role in roles:
                for user_role in claims['roles']:
                    if is_role_equivalent(user_role, required_role):
                        has_role = True
                        break
                if has_role:
                    break
                    
            if not has_role:
                return jsonify({'message': 'Insufficient privileges'}), 403
                
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Try importing roles_required from utils as a fallback
try:
    from backend.utils import roles_required as utils_roles_required
    # If import succeeds, use the imported version
    roles_required = utils_roles_required
except ImportError:
    # Keep using the locally defined version
    pass

# Auth routes
@blu.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Basic validation
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400

    try:
        email = data.get('email').lower()
        password = data.get('password')
        full_name = data.get('full_name')
        qualification = data.get('qualification')
        dob_str = data.get('dob')

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'User already exists'}), 400

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Convert date string to date object
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date() if dob_str else None

        # Create new user
        new_user = User(
            email=email,
            password=hashed_password,
            full_name=full_name,
            qualification=qualification,
            dob=dob,
            active=True  # Set default active status
        )

        # Add 'student' role by default (instead of 'user')
        student_role = Role.query.filter_by(name='student').first()
        if not student_role:
            student_role = Role(name='student', description='Student role')
            db.session.add(student_role)

        new_user.roles.append(student_role)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    except ValueError as ve:
        db.session.rollback()
        return jsonify({'message': f'Invalid date format: {str(ve)}'}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': 'An error occurred during registration'}), 500

@blu.route('/login', methods=['POST'])
def login():
    """Login and authenticate a user"""
    try:
        data = request.get_json()
        
        # Basic validation with better error messages
        if not data:
            current_app.logger.error("Login failed: No JSON data provided")
            return jsonify({'message': 'Request must contain valid JSON data'}), 400
            
        if not data.get('email'):
            return jsonify({'message': 'Email is required'}), 400
            
        if not data.get('password'):
            return jsonify({'message': 'Password is required'}), 400

        email = data.get('email').lower()
        password = data.get('password')

        # Log login attempt in debug mode
        if current_app.debug:
            current_app.logger.debug(f"Login attempt: {email}")
            
        user = User.query.filter_by(email=email).first()
        
        # More verbose error messages for debugging
        if not user:
            error_msg = f'No user found with email: {email}'
            current_app.logger.warning(error_msg)
            return jsonify({'message': error_msg if current_app.debug else 'Invalid credentials'}), 401

        # Check password
        if not user.check_password(password):
            error_msg = f'Incorrect password for user: {email}'
            current_app.logger.warning(error_msg)
            return jsonify({'message': error_msg if current_app.debug else 'Invalid credentials'}), 401

        if not user.active:
            return jsonify({'message': 'Account is deactivated'}), 403

        # Include user roles in JWT claims
        additional_claims = {
            'roles': [role.name for role in user.roles]
        }

        # Generate tokens
        access_token = create_access_token(
            identity=user.id,
            additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(
            identity=user.id,
            additional_claims=additional_claims
        )

        # Log successful login
        current_app.logger.info(f"User {email} logged in successfully")

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'roles': [role.name for role in user.roles]
            }
        }), 200
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'message': f'An error occurred during login: {str(e)}' if current_app.debug else 'An error occurred during login'}), 500

# Token refresh endpoint
@blu.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Include user roles in JWT claims
    additional_claims = {
        'roles': [role.name for role in user.roles]
    }
    
    # Create new access token
    access_token = create_access_token(
        identity=current_user_id,
        additional_claims=additional_claims
    )
    
    return jsonify({'access_token': access_token}), 200

@blu.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Log the user out by invalidating their token"""
    jti = get_jwt()["jti"]
    token_blocklist.add(jti)
    return jsonify({'message': 'Successfully logged out'}), 200

# Subject routes
@blu.route('/subjects', methods=['GET'])
def get_subjects():
    """Get all subjects"""
    try:
        # Removed cached_endpoint decorator to prevent caching issues
        subjects = Subject.query.all()
        result = []
        for subject in subjects:
            result.append({
                'id': subject.id,
                'name': subject.name,
                'description': subject.description
            })
            
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.error(f"Error in get_subjects: {str(e)}")
        return jsonify({"message": "Failed to retrieve subjects", "error": str(e)}), 500

@blu.route('/subjects', methods=['POST'])
@jwt_required()
@roles_required('admin')
def create_subject():
    data = request.get_json()
    
    subject = Subject(
        name=data.get('name'),
        description=data.get('description')
    )
    
    db.session.add(subject)
    db.session.commit()
    
    # Invalidate cache
    cache_data('all_subjects', None, timeout=0)
    
    return jsonify({
        'id': subject.id,
        'name': subject.name,
        'description': subject.description
    }), 201

@blu.route('/subjects/<int:subject_id>', methods=['PUT'])
@jwt_required()
@roles_required('admin')
def update_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    data = request.get_json()
    
    subject.name = data.get('name', subject.name)
    subject.description = data.get('description', subject.description)
    
    db.session.commit()
    
    # Invalidate cache
    cache_data('all_subjects', None, timeout=0)
    
    return jsonify({
        'id': subject.id,
        'name': subject.name,
        'description': subject.description
    }), 200

@blu.route('/subjects/<int:subject_id>', methods=['DELETE'])
@jwt_required()
@roles_required('admin')
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    
    db.session.delete(subject)
    db.session.commit()
    
    # Invalidate cache
    cache_data('all_subjects', None, timeout=0)
    
    return jsonify({'message': 'Subject deleted successfully'}), 200

@blu.route('/subjects/<int:subject_id>', methods=['GET'])
@jwt_required()
def get_subject(subject_id):
    """Get details for a specific subject"""
    subject = Subject.query.get_or_404(subject_id)
    
    # Count chapters and quizzes
    chapter_count = Chapter.query.filter_by(subject_id=subject_id).count()
    quiz_count = Quiz.query.join(Chapter).filter(Chapter.subject_id == subject_id).count()
    
    result = {
        'id': subject.id,
        'name': subject.name,
        'description': subject.description,
        'chapter_count': chapter_count,
        'quiz_count': quiz_count
    }
    
    return jsonify(result), 200

# Chapter routes
@blu.route('/subjects/<int:subject_id>/chapters', methods=['GET'])
@jwt_required()
def get_chapters(subject_id):
    """Get chapters for a subject"""
    # Removed cached_endpoint decorator to prevent caching issues
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    result = [{'id': chapter.id, 'name': chapter.name, 'description': chapter.description} 
              for chapter in chapters]
    
    return jsonify(result), 200

@blu.route('/subjects/<int:subject_id>/chapters', methods=['POST'])
@jwt_required()
@roles_required('admin')
def create_chapter(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    data = request.get_json()
    
    chapter = Chapter(
        name=data.get('name'),
        description=data.get('description'),
        subject_id=subject_id
    )
    
    db.session.add(chapter)
    db.session.commit()
    
    # Enhanced cache invalidation
    cache_data(f'chapters_subject_{subject_id}', None, timeout=0)
    cache_data('all_subjects', None, timeout=0)  # This triggers a full cache clear
    
    return jsonify({
        'id': chapter.id,
        'name': chapter.name,
        'description': chapter.description
    }), 201

@blu.route('/admin/chapters/<int:chapter_id>', methods=['PUT'])
@jwt_required()
@roles_required('admin')
def update_chapter(chapter_id):
    """Update a chapter (admin only)"""
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id
    data = request.get_json()
    
    # Update fields
    if 'name' in data:
        chapter.name = data['name']
    
    if 'description' in data:
        chapter.description = data['description']
    
    db.session.commit()
    
    # Enhanced cache invalidation
    cache_data(f'chapters_subject_{chapter.subject_id}', None, timeout=0)
    cache_data('all_subjects', None, timeout=0)  # This triggers a full cache clear
    
    return jsonify({
        'id': chapter.id,
        'name': chapter.name,
        'description': chapter.description,
        'subject_id': chapter.subject_id
    }), 200

@blu.route('/admin/chapters/<int:chapter_id>', methods=['DELETE'])
@jwt_required()
@roles_required('admin')
def delete_chapter(chapter_id):
    """Delete a chapter (admin only)"""
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id
    
    # Check if chapter has quizzes
    if chapter.quizzes:
        return jsonify({
            'message': 'Cannot delete chapter with quizzes. Remove all quizzes first.'
        }), 400
    
    db.session.delete(chapter)
    db.session.commit()
    
    # Enhanced cache invalidation
    cache_data(f'chapters_subject_{subject_id}', None, timeout=0)
    cache_data('all_subjects', None, timeout=0)  # This triggers a full cache clear
    
    return jsonify({'message': 'Chapter deleted successfully'}), 200

# Quiz routes
@blu.route('/chapters/<int:chapter_id>/quizzes', methods=['GET'])
@jwt_required()
def get_quizzes(chapter_id):
    """Get quizzes for a chapter"""
    # Removed cached_endpoint decorator to prevent caching issues
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    result = [{
        'id': quiz.id,
        'date_of_quiz': quiz.date_of_quiz.isoformat(),
        'time_duration': quiz.time_duration,
        'remarks': quiz.remarks,
        'question_count': len(quiz.questions)
    } for quiz in quizzes]
    
    return jsonify(result), 200

@blu.route('/chapters/<int:chapter_id>/quizzes', methods=['POST'])
@jwt_required()
@roles_required('admin')
def create_quiz(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    data = request.get_json()
    
    # Use today's date if date_of_quiz is not provided
    quiz_date = datetime.now().date()
    if data.get('date_of_quiz'):
        try:
            quiz_date = datetime.strptime(data.get('date_of_quiz'), '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    quiz = Quiz(
        chapter_id=chapter_id,
        date_of_quiz=quiz_date,
        time_duration=data.get('time_limit', data.get('time_duration', 30)),  # Support both field names
        remarks=data.get('description', data.get('remarks', ''))  # Support both field names
    )
    
    db.session.add(quiz)
    db.session.commit()
    
    # Enhanced cache invalidation - clear multiple related caches
    subject_id = chapter.subject_id
    cache_data(f'quizzes_chapter_{chapter_id}', None, timeout=0)
    cache_data('all_subjects', None, timeout=0)  # This triggers a full cache clear
    cache_data(f'chapters_subject_{subject_id}', None, timeout=0)
    
    return jsonify({
        'id': quiz.id,
        'date_of_quiz': quiz.date_of_quiz.isoformat(),
        'time_duration': quiz.time_duration,
        'remarks': quiz.remarks
    }), 201

@blu.route('/admin/quizzes/<int:quiz_id>', methods=['PUT'])
@jwt_required()
@roles_required('admin')
def update_quiz(quiz_id):
    """Update a quiz (admin only)"""
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter_id = quiz.chapter_id
    chapter = Chapter.query.get(chapter_id)
    data = request.get_json()
    
    if 'date_of_quiz' in data:
        quiz.date_of_quiz = datetime.strptime(data['date_of_quiz'], '%Y-%m-%d').date()
    
    if 'time_duration' in data:
        quiz.time_duration = data['time_duration']
    
    if 'remarks' in data:
        quiz.remarks = data['remarks']
    
    db.session.commit()
    
    # Enhanced cache invalidation - clear multiple related caches
    subject_id = chapter.subject_id if chapter else None
    cache_data(f'quizzes_chapter_{chapter_id}', None, timeout=0)
    cache_data('all_subjects', None, timeout=0)  # This triggers a full cache clear
    if subject_id:
        cache_data(f'chapters_subject_{subject_id}', None, timeout=0)
    
    return jsonify({
        'id': quiz.id,
        'date_of_quiz': quiz.date_of_quiz.isoformat(),
        'time_duration': quiz.time_duration,
        'remarks': quiz.remarks,
        'chapter_id': quiz.chapter_id
    }), 200

@blu.route('/admin/quizzes/<int:quiz_id>', methods=['DELETE'])
@jwt_required()
@roles_required('admin')
def delete_quiz(quiz_id):
    """Delete a quiz (admin only)"""
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter_id = quiz.chapter_id
    
    # Check if quiz has scores
    if Score.query.filter_by(quiz_id=quiz_id).count() > 0:
        return jsonify({
            'message': 'Cannot delete quiz with user attempts. Deactivate it instead.'
        }), 400
    
    # Delete all questions first
    Question.query.filter_by(quiz_id=quiz_id).delete()
    
    # Delete the quiz
    db.session.delete(quiz)
    db.session.commit()
    
    # Invalidate cache
    cache_data(f'quizzes_chapter_{chapter_id}', None, timeout=0)
    
    return jsonify({'message': 'Quiz deleted successfully'}), 200

@blu.route('/quizzes', methods=['GET'])
@jwt_required()
def list_quizzes():
    """Get a list of all quizzes"""
    # Optional filtering
    subject_id = request.args.get('subject_id')
    chapter_id = request.args.get('chapter_id')
    upcoming = request.args.get('upcoming', '').lower() == 'true'
    limit = request.args.get('limit', type=int)
    
    query = Quiz.query
    
    if subject_id:
        query = query.join(Chapter).filter(Chapter.subject_id == subject_id)
    
    if chapter_id:
        query = query.filter(Quiz.chapter_id == chapter_id)
    
    # Filter for upcoming quizzes
    if upcoming:
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        query = query.filter(Quiz.date_of_quiz >= today)
        # Sort by nearest date first
        query = query.order_by(Quiz.date_of_quiz)
    
    # Apply limit if specified
    if limit:
        query = query.limit(limit)
    
    # Get quizzes
    quizzes = query.all()
    
    # Get current user ID
    user_id = get_jwt_identity()
    
    result = []
    for quiz in quizzes:
        # Check if the user has attempted this quiz
        user_score = Score.query.filter_by(
            user_id=user_id,
            quiz_id=quiz.id
        ).order_by(Score.timestamp.desc()).first()
        
        quiz_data = {
            'id': quiz.id,
            'date_of_quiz': quiz.date_of_quiz.isoformat(),
            'time_duration': quiz.time_duration,
            'remarks': quiz.remarks,
            'chapter_id': quiz.chapter_id,
            'chapter_name': quiz.chapter.name,
            'subject_id': quiz.chapter.subject_id,
            'subject_name': quiz.chapter.subject.name,
            'questions_count': len(quiz.questions)
        }
        
        # Add user's score if available
        if user_score:
            quiz_data['user_score'] = {
                'id': user_score.id,
                'total_scored': user_score.total_scored,
                'total_questions': user_score.total_questions,
                'percentage': user_score.percentage,
                'timestamp': user_score.timestamp.isoformat()
            }
        
        result.append(quiz_data)
    
    return jsonify(result), 200

@blu.route('/quizzes/<int:quiz_id>', methods=['GET'])
@jwt_required()
def get_quiz(quiz_id):
    """Get details for a specific quiz"""
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if the user has attempted this quiz
    user_scores = Score.query.filter_by(
        user_id=get_jwt_identity(),
        quiz_id=quiz_id
    ).order_by(Score.timestamp.desc()).first()
    
    result = {
        'id': quiz.id,
        'date_of_quiz': quiz.date_of_quiz.isoformat(),
        'time_duration': quiz.time_duration,
        'remarks': quiz.remarks,
        'chapter_id': quiz.chapter_id,
        'chapter_name': quiz.chapter.name,
        'subject_id': quiz.chapter.subject_id,
        'subject_name': quiz.chapter.subject.name,
        'question_count': len(quiz.questions),
        'user_has_attempted': True if user_scores else False,
        'last_score': user_scores.percentage if user_scores else None
    }
    
    return jsonify(result), 200

# Question routes
@blu.route('/quizzes/<int:quiz_id>/questions', methods=['GET'])
@jwt_required()
def get_questions(quiz_id):
    """Get questions for a quiz"""
    # Removed cached_endpoint decorator to prevent caching issues
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    # If user is not admin, don't return correct answers
    is_admin = any(role.name == 'admin' for role in User.query.get(get_jwt_identity()).roles)
    
    result = [{
        'id': question.id,
        'question_statement': question.question_statement,
        'option1': question.option1,
        'option2': question.option2,
        'option3': question.option3,
        'option4': question.option4,
        'correct_option': question.correct_option if is_admin else None
    } for question in questions]
    
    return jsonify(result), 200

@blu.route('/quizzes/<int:quiz_id>/questions', methods=["POST"])
@jwt_required()
@roles_required('admin')
def create_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    data = request.get_json()
    
    question = Question(
        quiz_id=quiz_id,
        question_statement=data.get('question_statement'),
        option1=data.get('option1'),
        option2=data.get('option2'),
        option3=data.get('option3'),
        option4=data.get('option4'),
        correct_option=data.get('correct_option')
    )
    
    db.session.add(question)
    db.session.commit()
    
    # Enhanced cache invalidation
    chapter = quiz.chapter
    subject_id = chapter.subject_id if chapter else None
    
    # Clear multiple related caches
    cache_data(f'questions_quiz_{quiz_id}', None, timeout=0)
    cache_data(f'quizzes_chapter_{quiz.chapter_id}', None, timeout=0)
    if subject_id:
        cache_data(f'chapters_subject_{subject_id}', None, timeout=0)
    cache_data('all_subjects', None, timeout=0)  # This triggers a full cache clear
    
    return jsonify({
        'id': question.id,
        'question_statement': question.question_statement,
        'option1': question.option1,
        'option2': question.option2,
        'option3': question.option3,
        'option4': question.option4,
        'correct_option': question.correct_option
    }), 201

@blu.route('/admin/questions/<int:question_id>', methods=['PUT'])
@jwt_required()
@roles_required('admin')
def update_question(question_id):
    """Update a question (admin only)"""
    question = Question.query.get_or_404(question_id)
    data = request.get_json()
    
    # Update fields
    if 'question_statement' in data:
        question.question_statement = data['question_statement']
    
    if 'option1' in data:
        question.option1 = data['option1']
    
    if 'option2' in data:
        question.option2 = data['option2']
    
    if 'option3' in data:
        question.option3 = data['option3']
    
    if 'option4' in data:
        question.option4 = data['option4']
    
    if 'correct_option' in data:
        question.correct_option = data['correct_option']
    
    db.session.commit()
    
    # Invalidate cache
    cache_data(f'questions_quiz_{question.quiz_id}', None, timeout=0)
    
    return jsonify({
        'id': question.id,
        'question_statement': question.question_statement,
        'option1': question.option1,
        'option2': question.option2,
        'option3': question.option3,
        'option4': question.option4,
        'correct_option': question.correct_option,
        'quiz_id': question.quiz_id
    }), 200

@blu.route('/admin/questions/<int:question_id>', methods=['DELETE'])
@jwt_required()
@roles_required('admin')
def delete_question(question_id):
    """Delete a question (admin only)"""
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    
    db.session.delete(question)
    db.session.commit()
    
    # Invalidate cache
    cache_data(f'questions_quiz_{quiz_id}', None, timeout=0)
    
    return jsonify({'message': 'Question deleted successfully'}), 200

# Quiz Taking APIs
@blu.route('/quizzes/<int:quiz_id>/start', methods=['POST'])
@jwt_required()
def start_quiz(quiz_id):
    """Start a quiz attempt and get questions"""
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Get questions for this quiz
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if not questions:
        return jsonify({'message': 'No questions available for this quiz'}), 400
    
    # Create session token
    session_token = str(uuid.uuid4())
    
    # Record start time
    start_time = datetime.now().timestamp()
    
    # Create quiz session data
    quiz_session = {
        'quiz_id': quiz_id,
        'user_id': get_jwt_identity(),
        'start_time': start_time,
        'answers': {},
        'completed': False
    }
    
    # Increase timeout significantly (5x quiz duration + 30 minutes buffer)
    timeout_seconds = quiz.time_duration * 60 * 5 + 1800
    
    # Log session creation
    current_app.logger.info(f"Creating quiz session: {session_token} for quiz {quiz_id}, user {get_jwt_identity()}")
    
    cache_key = f'quiz_session_{session_token}'
    success = cache_data(cache_key, quiz_session, timeout=timeout_seconds)
    
    current_app.logger.info(f"Quiz session created: {session_token}, timeout: {timeout_seconds}s, cache success: {success}")
    
    return jsonify({
        'session_token': session_token,
        'quiz': {
            'id': quiz.id,
            'time_duration': quiz.time_duration,
            'question_count': len(questions)
        }
    }), 200

@blu.route('/quizzes/session/<session_token>/save', methods=['POST'])
@jwt_required()
def save_quiz_answers(session_token):
    """Save quiz answers during an active quiz session"""
    # Get session from cache
    cache_key = f'quiz_session_{session_token}'
    quiz_session = get_cached_data(cache_key)
    
    if not quiz_session:
        current_app.logger.warning(f"Quiz session not found in cache: {session_token} for user {get_jwt_identity()}")
        return jsonify({'message': 'Quiz session not found or expired'}), 404
    
    # Verify the current user is the one who started this session
    if quiz_session['user_id'] != get_jwt_identity():
        current_app.logger.warning(f"Unauthorized access to quiz session: {session_token}, expected user {quiz_session['user_id']}, got {get_jwt_identity()}")
        return jsonify({'message': 'Unauthorized access to quiz session'}), 403
    
    data = request.get_json()
    answers = data.get('answers', {})
    
    current_app.logger.info(f"Saving answers for session {session_token}: {len(answers)} answers")
    
    # Update answers in session
    quiz_session['answers'] = answers
    
    # Get quiz for extended timeout calculation
    quiz = Quiz.query.get(quiz_session['quiz_id'])
    if not quiz:
        current_app.logger.error(f"Quiz not found for session: {session_token}, quiz_id: {quiz_session['quiz_id']}")
        return jsonify({'message': 'Quiz not found'}), 404
    
    # Extended timeout - 5x quiz duration + 30 minutes buffer
    timeout_seconds = quiz.time_duration * 60 * 5 + 1800
    
    # Update quiz session in cache with extended timeout
    success = cache_data(cache_key, quiz_session, timeout=timeout_seconds)
    current_app.logger.info(f"Quiz answers saved for session: {session_token}, extended timeout: {timeout_seconds}s, success: {success}")
    
    return jsonify({'message': 'Answers saved successfully'}), 200

@blu.route('/quizzes/session/<session_token>/ping', methods=['GET'])
@jwt_required()
def ping_quiz_session(session_token):
    """Check if a quiz session is still valid"""
    cache_key = f'quiz_session_{session_token}'
    quiz_session = get_cached_data(cache_key)
    
    if not quiz_session:
        current_app.logger.warning(f"Quiz session not found in cache during ping: {session_token} for user {get_jwt_identity()}")
        return jsonify({'message': 'Quiz session not found or expired'}), 404
    
    # Verify the current user is the one who started this session
    if quiz_session['user_id'] != get_jwt_identity():
        current_app.logger.warning(f"Unauthorized access to quiz session: {session_token}, expected user {quiz_session['user_id']}, got {get_jwt_identity()}")
        return jsonify({'message': 'Unauthorized access to quiz session'}), 403
    
    # Get quiz for timeout calculation
    quiz = Quiz.query.get(quiz_session['quiz_id'])
    if not quiz:
        current_app.logger.error(f"Quiz not found for session: {session_token}, quiz_id: {quiz_session['quiz_id']}")
        return jsonify({'message': 'Quiz not found'}), 404
    
    # Extended timeout - 5x quiz duration + 30 minutes buffer
    timeout_seconds = quiz.time_duration * 60 * 5 + 1800
    
    # Update quiz session in cache with extended timeout
    success = cache_data(cache_key, quiz_session, timeout=timeout_seconds)
    
    return jsonify({
        'message': 'Session is valid',
        'quiz_id': quiz_session['quiz_id'],
        'start_time': quiz_session['start_time'],
        'completed': quiz_session.get('completed', False)
    }), 200

@blu.route('/quizzes/session/<session_token>/submit', methods=['POST'])
@jwt_required()
def submit_quiz(session_token):
    """Submit a quiz and calculate score"""
    # Get session from cache
    cache_key = f'quiz_session_{session_token}'
    quiz_session = get_cached_data(cache_key)
    
    current_app.logger.info(f"Processing quiz submission request for session: {session_token}, user: {get_jwt_identity()}")
    
    # Get request data for potential fallback
    request_data = request.get_json() or {}
    fallback_answers = request_data.get('fallback_answers')
    fallback_quiz_id = request_data.get('quiz_id')
    
    if not quiz_session:
        current_app.logger.warning(f"Quiz session not found in cache during submission: {session_token} for user {get_jwt_identity()}")
        
        # Attempt to recover using fallback data
        if fallback_answers and fallback_quiz_id:
            current_app.logger.info(f"Attempting to recover quiz submission with fallback data for quiz {fallback_quiz_id}")
            
            try:
                quiz = Quiz.query.get(fallback_quiz_id)
                if not quiz:
                    return jsonify({'message': 'Quiz not found for recovery'}), 404
                
                # Create a new session token for recovery
                recovery_token = str(uuid.uuid4())
                
                # Create temporary recovery session
                recovery_session = {
                    'quiz_id': int(fallback_quiz_id),
                    'user_id': get_jwt_identity(),
                    'start_time': datetime.now().timestamp() - 3600,  # Assume started 1 hour ago
                    'answers': fallback_answers,
                    'completed': False,
                    'is_recovery': True
                }
                
                # Cache the recovery session with long timeout
                recovery_key = f'quiz_session_{recovery_token}'
                cache_success = cache_data(recovery_key, recovery_session, timeout=3600)
                
                current_app.logger.info(f"Created recovery session {recovery_token} for quiz {fallback_quiz_id}, success: {cache_success}")
                
                # If caching succeeded, use the recovery session
                if cache_success:
                    quiz_session = recovery_session
                    session_token = recovery_token
                    cache_key = recovery_key
                else:
                    # If caching failed, still try to use the recovery data directly
                    quiz_session = recovery_session
            except Exception as e:
                current_app.logger.error(f"Recovery session creation failed: {str(e)}")
                return jsonify({'message': 'Quiz session not found or expired, and recovery failed'}), 404
        else:
            return jsonify({'message': 'Quiz session not found or expired'}), 404
    
    # Verify the current user is the one who started this session
    if quiz_session['user_id'] != get_jwt_identity():
        current_app.logger.warning(f"Unauthorized access to quiz session: {session_token}, expected user {quiz_session['user_id']}, got {get_jwt_identity()}")
        return jsonify({'message': 'Unauthorized access to quiz session'}), 403
    
    # Check if quiz was already submitted
    if quiz_session.get('completed'):
        current_app.logger.warning(f"Quiz already submitted: {session_token}")
        return jsonify({'message': 'Quiz already submitted'}), 400
        
    quiz_id = quiz_session['quiz_id']
    start_time = quiz_session['start_time']
    answers = quiz_session['answers']
    
    current_app.logger.info(f"Processing quiz submission: {session_token}, quiz_id: {quiz_id}, answers: {len(answers)}")
    
    # Get all questions for this quiz
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if not questions:
        current_app.logger.error(f"No questions found for quiz: {quiz_id}")
        return jsonify({'message': 'No questions found in quiz'}), 400
    
    # Calculate score
    correct_answers = 0
    total_questions = len(questions)
    
    for question in questions:
        q_id = str(question.id)
        if q_id in answers and int(answers[q_id]) == question.correct_option:
            correct_answers += 1
    
    # Calculate time taken in seconds
    end_time = datetime.now().timestamp()
    time_taken = int(end_time - start_time)
    
    # Save score to database
    try:
        score = Score(
            quiz_id=quiz_id,
            user_id=get_jwt_identity(),
            timestamp=datetime.fromtimestamp(end_time),
            total_scored=correct_answers,
            total_questions=total_questions,
            time_taken=time_taken  # Store the time taken in the score model
        )
        
        db.session.add(score)
        db.session.commit()
        
        current_app.logger.info(f"Score saved for quiz submission: {session_token}, score_id: {score.id}, correct: {correct_answers}/{total_questions}")
        
        # Mark quiz as completed and extend cache time to 1 hour
        quiz_session['completed'] = True
        cache_data(cache_key, quiz_session, timeout=3600)
        
        # Return score results
        return jsonify({
            'score_id': score.id,
            'correct_answers': correct_answers,
            'total_questions': total_questions,
            'percentage': score.percentage,
            'time_taken_seconds': time_taken
        }), 201
    except Exception as e:
        current_app.logger.error(f"Error saving quiz score: {str(e)}")
        db.session.rollback()
        return jsonify({'message': f'Error saving quiz score: {str(e)}'}), 500

# User Profile APIs
@blu.route('/users/me', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get current user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'full_name': user.full_name,
        'qualification': user.qualification,
        'dob': user.dob.isoformat() if user.dob else None,
        'roles': [role.name for role in user.roles]
    }), 200

@blu.route('/users/me', methods=['PUT'])
@jwt_required()
def update_user_profile():
    """Update current user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    
    # Update only allowed fields
    if 'full_name' in data:
        user.full_name = data['full_name']
    
    if 'qualification' in data:
        user.qualification = data['qualification']
    
    if 'dob' in data and data['dob']:
        user.dob = datetime.strptime(data['dob'], '%Y-%m-%d').date()
    
    # Don't allow email/password updates through this endpoint
    
    db.session.commit()
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'full_name': user.full_name,
        'qualification': user.qualification,
        'dob': user.dob.isoformat() if user.dob else None,
        'roles': [role.name for role in user.roles]
    }), 200

# Admin User Management APIs
@blu.route('/admin/users', methods=['GET'])
@jwt_required()
@roles_required('admin')
def get_all_users():
    """Get all users (admin only)"""
    users = User.query.all()
    
    result = [{
        'id': user.id,
        'email': user.email,
        'full_name': user.full_name,
        'qualification': user.qualification,
        'dob': user.dob.isoformat() if user.dob else None,
        'roles': [role.name for role in user.roles],
        'active': user.active
    } for user in users]
    
    return jsonify(result), 200

@blu.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@roles_required('admin')
def update_user(user_id):
    """Update a user (admin only)"""
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    
    # Update user fields
    if 'email' in data:
        user.email = data['email']
    if 'full_name' in data:
        user.full_name = data['full_name']
    if 'qualification' in data:
        user.qualification = data['qualification']
    if 'dob' in data and data['dob']:
        user.dob = datetime.strptime(data['dob'], '%Y-%m-%d').date()
    if 'active' in data:
        user.active = data['active']
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    
    # Handle role updates
    if 'roles' in data and isinstance(data['roles'], list):
        # Clear existing roles
        user.roles = []
        
        # Add new roles
        for role_name in data['roles']:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name, description=f'{role_name} role')
                db.session.add(role)
            if role not in user.roles:
                user.roles.append(role)
    
    db.session.commit()
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'full_name': user.full_name,
        'qualification': user.qualification,
        'dob': user.dob.isoformat() if user.dob else None,
        'roles': [role.name for role in user.roles],
        'active': user.active
    }), 200

@blu.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@roles_required('admin')
def delete_user(user_id):
    """Delete a user (admin only)"""
    user = User.query.get_or_404(user_id)
    
    # Check if user is admin
    if any(role.name == 'admin' for role in user.roles):
        return jsonify({'message': 'Cannot delete admin users'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200

# Add these routes after your existing routes

# Score APIs
@blu.route('/scores', methods=['GET'])
@jwt_required()
def get_user_scores():
    """Get scores for the current user"""
    # Optional filtering by quiz or date
    quiz_id = request.args.get('quiz_id')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    query = Score.query.filter_by(user_id=get_jwt_identity())
    
    if quiz_id:
        query = query.filter_by(quiz_id=int(quiz_id))
    
    if from_date:
        from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
        query = query.filter(Score.timestamp >= from_datetime)
    
    if to_date:
        to_datetime = datetime.strptime(to_date, '%Y-%m-%d')
        to_datetime = to_datetime.replace(hour=23, minute=59, second=59)
        query = query.filter(Score.timestamp <= to_datetime)
    
    scores = query.order_by(Score.timestamp.desc()).all()
    
    result = [{
        'id': score.id,
        'quiz_id': score.quiz_id,
        'timestamp': score.timestamp.isoformat(),
        'total_scored': score.total_scored,
        'total_questions': score.total_questions,
        'percentage': score.percentage,
        'quiz_info': {
            'date_of_quiz': score.quiz.date_of_quiz.isoformat(),
            'time_duration': score.quiz.time_duration,
            'chapter_name': score.quiz.chapter.name,
            'subject_name': score.quiz.chapter.subject.name
        } if score.quiz else None
    } for score in scores]
    
    return jsonify(result), 200

@blu.route('/scores/<int:score_id>', methods=['GET'])
@jwt_required()
def get_score_detail(score_id):
    """Get detailed information about a specific score"""
    # For regular users, only return their own scores
    query = Score.query.filter_by(id=score_id)
    
    if not any(role.name == 'admin' for role in User.query.get(get_jwt_identity()).roles):
        query = query.filter_by(user_id=get_jwt_identity())
    
    score = query.first_or_404()
    
    # Get quiz information
    quiz_info = None
    if score.quiz:
        # Get total scores for this quiz to calculate average
        all_quiz_scores = Score.query.filter_by(quiz_id=score.quiz_id).all()
        avg_score = 0
        if all_quiz_scores:
            avg_score = round(sum(s.percentage for s in all_quiz_scores) / len(all_quiz_scores), 1)
        
        # Get user's rank for this quiz (optional)
        user_rank = "N/A"
        try:
            # Get all scores for this quiz
            # Can't use percentage directly in order_by since it's a property
            all_quiz_scores = Score.query.filter_by(quiz_id=score.quiz_id).all()
            
            # Sort scores manually by percentage in descending order
            ranked_scores = sorted(all_quiz_scores, key=lambda s: s.percentage, reverse=True)
            
            # Find the position of the current score
            for i, s in enumerate(ranked_scores):
                if s.id == score_id:
                    user_rank = f"{i+1}/{len(ranked_scores)}"
                    break
        except Exception as e:
            current_app.logger.error(f"Error calculating rank: {str(e)}")
        
        quiz_info = {
            'quiz_id': score.quiz_id,
            'date_of_quiz': score.quiz.date_of_quiz.isoformat(),
            'time_duration': score.quiz.time_duration,
            'chapter_name': score.quiz.chapter.name,
            'subject_name': score.quiz.chapter.subject.name,
            'chapter_id': score.quiz.chapter_id,
            'subject_id': score.quiz.chapter.subject_id,
            'average_score': avg_score,
            'rank': user_rank
        }
    
    # Calculate and format time taken (if available)
    time_taken = None
    if hasattr(score, 'time_taken') and score.time_taken:
        # Convert to seconds for frontend formatting
        time_taken_seconds = score.time_taken
        # Format as HH:MM:SS for display
        hours = time_taken_seconds // 3600
        minutes = (time_taken_seconds % 3600) // 60
        seconds = time_taken_seconds % 60
        time_taken = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        # Add to quiz_info
        quiz_info['time_taken'] = time_taken
        quiz_info['time_taken_seconds'] = time_taken_seconds
    else:
        # If no time_taken available, use quiz duration as fallback
        quiz_duration_minutes = score.quiz.time_duration
        time_taken = f"{quiz_duration_minutes // 60:02d}:{quiz_duration_minutes % 60:02d}:00"
        quiz_info['time_taken'] = time_taken
        quiz_info['time_taken_seconds'] = quiz_duration_minutes * 60

    result = {
        'id': score.id,
        'quiz_id': score.quiz_id,
        'user_id': score.user_id,
        'timestamp': score.timestamp.isoformat(),
        'total_scored': score.total_scored,
        'total_questions': score.total_questions,
        'percentage': score.percentage,
        'quiz_info': quiz_info,
        'user_info': {
            'email': score.user.email,
            'full_name': score.user.full_name
        } if score.user else None
    }
    
    return jsonify(result), 200

# Analytics APIs
@blu.route('/analytics/user', methods=['GET'])
@jwt_required()
def get_user_analytics():
    """Get performance analytics for current user"""
    # Get all scores for the user
    user_id = get_jwt_identity()
    scores = Score.query.filter_by(user_id=user_id).all()
    
    if not scores:
        return jsonify({
            'message': 'No quiz attempts found',
            'total_quizzes': 0,
            'average_score': 0,
            'best_score': 0,
            'subjects_count': 0,
            'recent_scores': [],
            'subject_performance': []
        }), 200
    
    # Group quiz performance by subject
    subject_performance = {}
    unique_subjects = set()
    best_score = 0
    
    for score in scores:
        # Track best score
        if score.percentage > best_score:
            best_score = score.percentage
            
        # Skip incomplete records
        if not score.quiz or not score.quiz.chapter or not score.quiz.chapter.subject:
            continue
            
        subject_id = score.quiz.chapter.subject.id
        subject_name = score.quiz.chapter.subject.name
        unique_subjects.add(subject_id)
        
        if subject_id not in subject_performance:
            subject_performance[subject_id] = {
                'subject_id': subject_id,
                'subject_name': subject_name,
                'total_quizzes': 0,
                'total_score': 0,
                'average_score': 0
            }
        
        subject_performance[subject_id]['total_quizzes'] += 1
        subject_performance[subject_id]['total_score'] += score.percentage
    
    # Calculate averages for each subject
    for subject_id in subject_performance:
        total_quizzes = subject_performance[subject_id]['total_quizzes']
        total_score = subject_performance[subject_id]['total_score']
        
        if total_quizzes > 0:
            subject_performance[subject_id]['average_score'] = round(total_score / total_quizzes, 2)
    
    # Get recent scores (limit to 5)
    recent_scores = []
    for score in sorted(scores, key=lambda x: x.timestamp, reverse=True)[:5]:
        if not score.quiz:
            continue
            
        quiz_chapter_subject = "Unknown"
        if score.quiz.chapter and score.quiz.chapter.subject:
            quiz_chapter_subject = f"{score.quiz.chapter.subject.name} - {score.quiz.chapter.name}"
        
        recent_scores.append({
            'id': score.id,
            'quiz_id': score.quiz_id,
            'timestamp': score.timestamp.isoformat(),
            'total_scored': score.total_scored,
            'total_questions': score.total_questions,
            'percentage': score.percentage,
            'quiz_chapter_subject': quiz_chapter_subject,
            'subject_name': score.quiz.chapter.subject.name if score.quiz.chapter and score.quiz.chapter.subject else 'Unknown',
            'chapter_name': score.quiz.chapter.name if score.quiz.chapter else 'Unknown'
        })
    
    # Prepare result with all needed stats
    result = {
        'total_quizzes': len(scores),
        'average_score': round(sum(score.percentage for score in scores) / len(scores), 2),
        'best_score': best_score,
        'subjects_count': len(unique_subjects),
        'recent_scores': recent_scores,
        'subject_performance': list(subject_performance.values())
    }
    
    return jsonify(result), 200

@blu.route('/admin/analytics', methods=['GET'])
@jwt_required()
@roles_required('admin')
def get_admin_analytics():
    """Get admin dashboard analytics"""
    try:
        # Get date filter parameters
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        
        # Build base query for scores with date filtering
        scores_query = Score.query
        
        if from_date:
            from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
            scores_query = scores_query.filter(Score.timestamp >= from_datetime)
        
        if to_date:
            to_datetime = datetime.strptime(to_date, '%Y-%m-%d')
            to_datetime = to_datetime.replace(hour=23, minute=59, second=59)
            scores_query = scores_query.filter(Score.timestamp <= to_datetime)
        
        # Count total users, quizzes, subjects, questions
        total_users = User.query.filter(~User.roles.any(Role.name == 'admin')).count()
        total_subjects = Subject.query.count()
        total_quizzes = Quiz.query.count()
        total_questions = Question.query.count()
        total_attempts = scores_query.count()
        
        # Calculate average score percentage
        avg_score = 0
        if total_attempts > 0:
            avg_score_result = db.session.query(func.avg(Score.total_scored * 100.0 / Score.total_questions)).scalar()
            avg_score = round(avg_score_result or 0, 2)
        
        # Calculate completion rate (% of students who completed at least one quiz)
        students_with_quizzes = db.session.query(Score.user_id).distinct().count()
        completion_rate = round((students_with_quizzes / total_users * 100) if total_users > 0 else 0, 2)
        
        # Get recent quiz attempts (last 10)
        recent_attempts = scores_query.order_by(Score.timestamp.desc()).limit(10).all()
        recent_attempts_data = [{
            'id': score.id,
            'user_email': score.user.email if score.user else 'Unknown',
            'user_name': score.user.full_name if score.user else 'Unknown',
            'quiz_id': score.quiz_id,
            'timestamp': score.timestamp.isoformat(),
            'percentage': score.percentage,
            'quiz_info': {
                'subject': score.quiz.chapter.subject.name if score.quiz and score.quiz.chapter else 'Unknown',
                'chapter': score.quiz.chapter.name if score.quiz and score.quiz.chapter else 'Unknown',
            } if score.quiz else {'subject': 'Unknown', 'chapter': 'Unknown'}
        } for score in recent_attempts]
        
        # Subject-wise quiz statistics
        subjects = Subject.query.all()
        subject_stats = []
        
        for subject in subjects:
            quiz_count = 0
            question_count = 0
            attempt_count = 0
            avg_subject_score = 0
            
            # Count quizzes and questions per subject
            for chapter in subject.chapters:
                for quiz in chapter.quizzes:
                    quiz_count += 1
                    question_count += len(quiz.questions)
                    
                    # Count attempts and calculate average score for this subject
                    quiz_attempts = scores_query.filter(Score.quiz_id == quiz.id).all()
                    attempt_count += len(quiz_attempts)
                    
                    if quiz_attempts:
                        avg_subject_score += sum(attempt.percentage for attempt in quiz_attempts)
            
            # Calculate average score for this subject
            if attempt_count > 0:
                avg_subject_score = round(avg_subject_score / attempt_count, 2)
            
            subject_stats.append({
                'id': subject.id,
                'name': subject.name,
                'quiz_count': quiz_count,
                'question_count': question_count,
                'attempt_count': attempt_count,
                'avg_score': avg_subject_score
            })
        
        # Get top performing students
        top_students_query = db.session.query(
            Score.user_id,
            func.avg(Score.total_scored * 100.0 / Score.total_questions).label('avg_score'),
            func.count(Score.id).label('quiz_count')
        ).group_by(Score.user_id).order_by(db.desc('avg_score')).limit(5)
        
        top_students = []
        for user_id, avg_score, quiz_count in top_students_query:
            user = User.query.get(user_id)
            if not user:
                continue
                
            # Find best subject for this student
            user_scores = scores_query.filter(Score.user_id == user_id).all()
            subject_scores = {}
            
            for score in user_scores:
                if score.quiz and score.quiz.chapter and score.quiz.chapter.subject:
                    subject_id = score.quiz.chapter.subject.id
                    subject_name = score.quiz.chapter.subject.name
                    
                    if subject_id not in subject_scores:
                        subject_scores[subject_id] = {
                            'name': subject_name,
                            'total': 0,
                            'count': 0
                        }
                        
                    subject_scores[subject_id]['total'] += score.percentage
                    subject_scores[subject_id]['count'] += 1
            
            # Find subject with highest average score
            best_subject = 'N/A'
            best_score = 0
            
            for subject_id, data in subject_scores.items():
                if data['count'] > 0:
                    avg = data['total'] / data['count']
                    if avg > best_score:
                        best_score = avg
                        best_subject = data['name']
            
            top_students.append({
                'id': user_id,
                'name': user.full_name or 'Unknown',
                'email': user.email,
                'quizzesCompleted': quiz_count,
                'avgScore': round(avg_score, 2),
                'bestSubject': best_subject
            })
        
        # Get quiz attempts over time
        time_periods = request.args.get('groupBy', 'day')
        
        # Group scores by day, week, or month
        attempt_data = []
        
        if scores_query.count() > 0:
            if time_periods == 'day':
                # Last 14 days
                for i in range(13, -1, -1):
                    date = datetime.now() - timedelta(days=i)
                    day_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
                    day_end = date.replace(hour=23, minute=59, second=59, microsecond=999999)
                    
                    count = scores_query.filter(
                        Score.timestamp >= day_start,
                        Score.timestamp <= day_end
                    ).count()
                    
                    attempt_data.append({
                        'date': day_start.strftime('%Y-%m-%d'),
                        'label': day_start.strftime('%b %d'),
                        'count': count
                    })
            
            elif time_periods == 'week':
                # Last 10 weeks
                for i in range(9, -1, -1):
                    week_start = datetime.now() - timedelta(days=i*7 + datetime.now().weekday())
                    week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
                    week_end = week_start + timedelta(days=6, hours=23, minutes=59, seconds=59)
                    
                    count = scores_query.filter(
                        Score.timestamp >= week_start,
                        Score.timestamp <= week_end
                    ).count()
                    
                    attempt_data.append({
                        'date': week_start.strftime('%Y-%m-%d'),
                        'label': f"{week_start.strftime('%b %d')} - {week_end.strftime('%b %d')}",
                        'count': count
                    })
            
            elif time_periods == 'month':
                # Last 12 months
                for i in range(11, -1, -1):
                    current_date = datetime.now()
                    month_start = datetime(current_date.year, current_date.month, 1) - relativedelta(months=i)
                    
                    if i > 0:
                        month_end = datetime(current_date.year, current_date.month, 1) - relativedelta(months=i-1, days=1)
                    else:
                        # For current month, use today as the end date
                        month_end = datetime.now()
                    
                    month_end = month_end.replace(hour=23, minute=59, second=59)
                    
                    count = scores_query.filter(
                        Score.timestamp >= month_start,
                        Score.timestamp <= month_end
                    ).count()
                    
                    attempt_data.append({
                        'date': month_start.strftime('%Y-%m-%d'),
                        'label': month_start.strftime('%b %Y'),
                        'count': count
                    })
        
        # Calculate growth metrics (compared to previous period)
        previous_period_query = Score.query
        
        if from_date and to_date:
            current_period_days = (datetime.strptime(to_date, '%Y-%m-%d') - datetime.strptime(from_date, '%Y-%m-%d')).days
            previous_start = datetime.strptime(from_date, '%Y-%m-%d') - timedelta(days=current_period_days)
            previous_end = datetime.strptime(from_date, '%Y-%m-%d') - timedelta(days=1)
            
            previous_period_query = previous_period_query.filter(
                Score.timestamp >= previous_start,
                Score.timestamp <= previous_end
            )
        else:
            # Default to comparing with previous 30 days
            today = datetime.now()
            thirty_days_ago = today - timedelta(days=30)
            sixty_days_ago = today - timedelta(days=60)
            
            previous_period_query = previous_period_query.filter(
                Score.timestamp >= sixty_days_ago,
                Score.timestamp <= thirty_days_ago
            )
        
        # Calculate growth metrics
        prev_attempts = previous_period_query.count()
        prev_users = db.session.query(Score.user_id).filter(
            Score.id.in_([s.id for s in previous_period_query])
        ).distinct().count()
        
        prev_avg_score = 0
        if prev_attempts > 0:
            prev_scores = [s.percentage for s in previous_period_query]
            prev_avg_score = sum(prev_scores) / len(prev_scores)
        
        # Calculate growth percentages
        user_growth = calculate_growth(prev_users, students_with_quizzes)
        attempts_growth = calculate_growth(prev_attempts, total_attempts)
        score_growth = calculate_growth(prev_avg_score, avg_score)
        
        result = {
            'counts': {
                'users': total_users,
                'subjects': total_subjects,
                'quizzes': total_quizzes,
                'questions': total_questions,
                'attempts': total_attempts
            },
            'stats': {
                'totalUsers': total_users,
                'userGrowth': user_growth,
                'quizAttempts': total_attempts,
                'attemptsGrowth': attempts_growth,
                'avgScore': avg_score,
                'scoreGrowth': score_growth,
                'completionRate': completion_rate,
                'completionGrowth': 0  # Placeholder for now
            },
            'recent_attempts': recent_attempts_data,
            'subject_stats': subject_stats,
            'topStudents': top_students,
            'attemptsByPeriod': attempt_data
        }
        
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.error(f"Error in admin analytics: {str(e)}")
        return jsonify({'message': f'Error generating analytics: {str(e)}'}), 500

def calculate_growth(previous, current):
    """Helper function to calculate growth percentage"""
    if previous == 0:
        return 100 if current > 0 else 0
    
    return round(((current - previous) / previous) * 100, 1)

# Add these routes after your existing routes

# Export APIs
@blu.route('/export/scores', methods=['POST'])
@jwt_required()
def export_user_scores():
    """Trigger an async job to export the current user's quiz scores as CSV"""
    from backend.tasks import export_user_scores_task, get_task_status
    
    try:
        user_id = get_jwt_identity()
        
        # Launch the export task asynchronously
        task = export_user_scores_task.delay(user_id)
        
        return jsonify({
            'status': 'success',
            'task_id': task.id,
            'message': 'Export started. You will be notified when complete.',
            'check_status_url': f"/api/tasks/{task.id}"
        }), 202
    
    except Exception as e:
        current_app.logger.error(f"Error starting export: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to start export: {str(e)}"
        }), 500

@blu.route('/admin/export/users', methods=['POST'])
@jwt_required()
@roles_required('admin')
def export_users_data():
    """Trigger an async job to export all users' data for admin"""
    from backend.tasks import export_users_data_task
    
    try:
        admin_id = get_jwt_identity()
        
        # Get optional filters from request
        filters = request.get_json() if request.is_json else None
        
        # Launch the export task asynchronously
        task = export_users_data_task.delay(admin_id, filters)
        
        return jsonify({
            'status': 'success',
            'task_id': task.id,
            'message': 'Export started. You will be notified when complete.',
            'check_status_url': f"/api/tasks/{task.id}"
        }), 202
    
    except Exception as e:
        current_app.logger.error(f"Error starting admin export: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to start export: {str(e)}"
        }), 500

@blu.route('/tasks/<task_id>', methods=['GET'])
@jwt_required()
def get_task_status(task_id):
    """Get the status of an asynchronous task"""
    from backend.tasks import get_task_status as get_status
    
    try:
        result = get_status(task_id)
        
        if not result:
            return jsonify({
                'status': 'error',
                'message': 'Task not found'
            }), 404
        
        return jsonify(result), 200
    
    except Exception as e:
        current_app.logger.error(f"Error getting task status: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Error getting task status: {str(e)}"
        }), 500

@blu.route('/export/download/<filename>', methods=['GET'])
@jwt_required()
def download_export(filename):
    """Download a generated export file"""
    try:
        # Get the export folder from config
        export_folder = current_app.config.get('EXPORT_FOLDER')
        
        # Validate filename to prevent directory traversal attacks
        if '..' in filename or '/' in filename:
            return jsonify({
                'status': 'error',
                'message': 'Invalid filename'
            }), 400
        
        # Build the full path
        file_path = os.path.join(export_folder, filename)
        
        # Check if the file exists
        if not os.path.exists(file_path):
            return jsonify({
                'status': 'error',
                'message': 'File not found'
            }), 404
        
        # Check if the current user is authorized to access this file
        user_id = get_jwt_identity()
        
        # If it's an admin export, only admins should access it
        is_admin = False
        claims = get_jwt()
        if 'roles' in claims:
            is_admin = any(role == 'admin' for role in claims['roles'])
        
        if 'admin_' in filename and not is_admin:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403
        
        # If it's a user export, only the owner should access it
        if f'user_{user_id}_' not in filename and not is_admin:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403
        
        # Return the file as an attachment
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='text/csv'
        )
    
    except Exception as e:
        current_app.logger.error(f"Error downloading export: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to download export: {str(e)}"
        }), 500

# Add these routes to your existing API file

# Authentication routes
@blu.route('/reset-password', methods=['POST'])
def reset_password():
    """Request a password reset link"""
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if user exists for security reasons
        return jsonify({'message': 'If your email is registered, you will receive reset instructions'}), 200
    
    # Send password reset email
    # This implementation is a placeholder - real implementation would use email service
    
    return jsonify({'message': 'Password reset instructions sent to your email'}), 200

@blu.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change the user's password"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    # Validate input
    if not current_password or not new_password:
        return jsonify({'message': 'Both current and new password are required'}), 400
    
    # Get current user
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'message': 'User not found'}), 404
        
    # Use verify_password here as well
    if not verify_password(user, current_password):
        return jsonify({'message': 'Current password is incorrect'}), 400
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'}), 200

# Quiz results
@blu.route('/quizzes/<int:quiz_id>/result', methods=['GET'])
@jwt_required()
def get_quiz_result(quiz_id):
    """Get results for a specific quiz"""
    try:
        # Check if the quiz exists first
        from backend.models import Quiz
        quiz = Quiz.query.get(quiz_id)
        if not quiz:
            return jsonify({'message': 'Quiz not found'}), 404
            
        # Find the most recent score for this quiz by this user
        user_id = get_jwt_identity()
        current_app.logger.debug(f"Looking for results for quiz {quiz_id} and user {user_id}")
        
        score = Score.query.filter_by(
            user_id=user_id,
            quiz_id=quiz_id
        ).order_by(Score.timestamp.desc()).first()
        
        if not score:
            return jsonify({'message': 'No results found for this quiz'}), 404
        
        result = {
            'id': score.id,
            'quiz_id': score.quiz_id,
            'timestamp': score.timestamp.isoformat(),
            'total_scored': score.total_scored,
            'total_questions': score.total_questions,
            'percentage': score.percentage,
            'quiz_info': {
                'date_of_quiz': score.quiz.date_of_quiz.isoformat(),
                'time_duration': score.quiz.time_duration,
                'chapter_name': score.quiz.chapter.name,
                'subject_name': score.quiz.chapter.subject.name
            } if score.quiz else None
        }
        
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.error(f"Error retrieving quiz result: {str(e)}")
        return jsonify({'message': f'Error retrieving quiz result: {str(e)}'}), 500

# Search functionality
@blu.route('/search', methods=['GET'])
@jwt_required()
def search():
    """Enhanced search functionality across users, subjects, chapters, quizzes, and user scores"""
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'all')  # Default to 'all'
    
    if not query or len(query) < 2:
        return jsonify({'message': 'Search query must be at least 2 characters'}), 400
    
    # Get current user's roles and ID
    current_user_id = get_jwt_identity()
    user_claims = get_jwt()
    user_roles = user_claims.get('roles', [])
    is_admin = 'admin' in user_roles
    
    # Search pattern
    search_pattern = f'%{query}%'
    results = {}
    
    # ADMIN SEARCHES - only if user is an admin
    if is_admin and (search_type == 'all' or search_type == 'users'):
        users = User.query.filter(
            (User.email.ilike(search_pattern)) | 
            (User.full_name.ilike(search_pattern))
        ).all()
        
        results['users'] = [{
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'roles': [role.name for role in user.roles],
            'active': user.active
        } for user in users]
    
    # Subject search - available to all users
    if search_type == 'all' or search_type == 'subjects':
        subjects = Subject.query.filter(
            (Subject.name.ilike(search_pattern)) |
            (Subject.description.ilike(search_pattern))
        ).all()
        
        results['subjects'] = [{
            'id': subject.id,
            'name': subject.name,
            'description': subject.description,
            'chapter_count': len(subject.chapters)
        } for subject in subjects]
    
    # Chapter search - available to all users
    if search_type == 'all' or search_type == 'chapters':
        chapters = Chapter.query.filter(
            (Chapter.name.ilike(search_pattern)) |
            (Chapter.description.ilike(search_pattern))
        ).all()
        
        results['chapters'] = [{
            'id': chapter.id,
            'name': chapter.name,
            'description': chapter.description,
            'subject_id': chapter.subject_id,
            'subject_name': chapter.subject.name if chapter.subject else None
        } for chapter in chapters]
    
    # Quiz search - available to all users
    if search_type == 'all' or search_type == 'quizzes':
        # More comprehensive search includes quiz remarks or date strings
        quizzes = Quiz.query.filter(
            (Quiz.remarks.ilike(search_pattern)) |
            (func.cast(Quiz.date_of_quiz, db.String).ilike(search_pattern))
        ).all()
        
        results['quizzes'] = [{
            'id': quiz.id,
            'date_of_quiz': quiz.date_of_quiz.isoformat() if quiz.date_of_quiz else None,
            'time_duration': quiz.time_duration,
            'remarks': quiz.remarks,
            'chapter_id': quiz.chapter_id,
            'chapter_name': quiz.chapter.name if quiz.chapter else None,
            'subject_name': quiz.chapter.subject.name if quiz.chapter and quiz.chapter.subject else None,
            'question_count': len(quiz.questions) if hasattr(quiz, 'questions') else 0
        } for quiz in quizzes]
    
    # USER SCORE SEARCHES - specific to the current user or available to admin
    if search_type == 'all' or search_type == 'scores':
        # For admins: search all scores if specified
        if is_admin and request.args.get('all_scores') == 'true':
            # Admin can search across all user scores
            scores_query = Score.query.join(Quiz).join(Chapter).join(Subject).filter(
                (Subject.name.ilike(search_pattern)) |
                (Chapter.name.ilike(search_pattern)) |
                (Quiz.remarks.ilike(search_pattern)) |
                (User.full_name.ilike(search_pattern))
            )
        else:
            # Regular users can only search their own scores
            scores_query = Score.query.filter(Score.user_id == current_user_id).join(Quiz).join(Chapter).join(Subject).filter(
                (Subject.name.ilike(search_pattern)) |
                (Chapter.name.ilike(search_pattern)) |
                (Quiz.remarks.ilike(search_pattern))
            )
        
        scores = scores_query.order_by(Score.timestamp.desc()).all()
        
        results['scores'] = [{
            'id': score.id,
            'quiz_id': score.quiz_id,
            'quiz_name': f"{score.quiz.chapter.subject.name} - {score.quiz.chapter.name}" if score.quiz and score.quiz.chapter and score.quiz.chapter.subject else "Unknown Quiz",
            'timestamp': score.timestamp.isoformat(),
            'score': score.score,
            'total_questions': score.total_questions,
            'percentage': score.percentage,
            'user_name': score.user.full_name if is_admin and score.user else None
        } for score in scores]
    
    return jsonify(results), 200

# Admin dashboard summary
@blu.route('/admin/summary', methods=['GET'])
@jwt_required()
@roles_required('admin')
def admin_summary():
    """Get a summary of system data for admin dashboard"""
    # User stats
    total_users = User.query.filter(~User.roles.any(Role.name == 'admin')).count()
    active_users = User.query.filter(
        User.active == True,
        ~User.roles.any(Role.name == 'admin')
    ).count()
    
    # Content stats
    total_subjects = Subject.query.count()
    total_chapters = Chapter.query.count()
    total_quizzes = Quiz.query.count()
    total_questions = Question.query.count()
    
    # Quiz activity
    total_attempts = Score.query.count()
    
    # Recent activity (last 10 scores)
    recent_scores = Score.query.order_by(Score.timestamp.desc()).limit(10).all()
    recent_activity = [{
        'id': score.id,
        'user_email': score.user.email if score.user else None,
        'user_name': score.user.full_name if score.user else None,
        'quiz_id': score.quiz_id,
        'quiz_name': f"{score.quiz.chapter.subject.name} - {score.quiz.chapter.name}" if score.quiz else None,
        'timestamp': score.timestamp.isoformat(),
        'percentage': score.percentage
    } for score in recent_scores]
    
    return jsonify({
        'user_stats': {
            'total': total_users,
            'active': active_users,
            'inactive': total_users - active_users
        },
        'content_stats': {
            'subjects': total_subjects,
            'chapters': total_chapters,
            'quizzes': total_quizzes,
            'questions': total_questions
        },
        'quiz_stats': {
            'total_attempts': total_attempts
        },
        'recent_activity': recent_activity
    }), 200

@blu.route('/auth/token-refresh', methods=['POST'])
@jwt_required()
def refresh_token():
    """Refresh the user's authentication token"""
    # Get current user ID from JWT
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Include user roles in JWT claims
    additional_claims = {
        'roles': [role.name for role in user.roles]
    }
    
    # Create new access token
    new_token = create_access_token(
        identity=user_id,
        additional_claims=additional_claims
    )
    
    return jsonify({
        'token': new_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'roles': [role.name for role in user.roles]
        }
    }), 200

@blu.route('/user/monthly-report', methods=['GET'])
@jwt_required()
def get_monthly_report():
    """Get user's monthly performance report"""
    from datetime import datetime, timedelta
    
    # Get the first day of current month
    today = datetime.now()
    start_date = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Get all scores for this month
    scores = Score.query.filter(
        Score.user_id == get_jwt_identity(),
        Score.timestamp >= start_date
    ).all()
    
    # Calculate statistics
    total_quizzes = len(scores)
    if total_quizzes == 0:
        return jsonify({
            'message': 'No quizzes taken this month',
            'month': start_date.strftime('%B %Y'),
            'stats': None
        }), 200
    
    avg_score = sum(score.percentage for score in scores) / total_quizzes
    
    # Group by subject
    subject_stats = {}
    for score in scores:
        if not score.quiz:
            continue
            
        subject_name = score.quiz.chapter.subject.name
        if subject_name not in subject_stats:
            subject_stats[subject_name] = {
                'quizzes': 0,
                'total_score': 0
            }
        
        subject_stats[subject_name]['quizzes'] += 1
        subject_stats[subject_name]['total_score'] += score.percentage
    
    # Calculate subject averages
    for subject in subject_stats:
        subject_stats[subject]['average'] = round(
            subject_stats[subject]['total_score'] / 
            subject_stats[subject]['quizzes'], 2
        )
    
    return jsonify({
        'month': start_date.strftime('%B %Y'),
        'total_quizzes': total_quizzes,
        'average_score': round(avg_score, 2),
        'subjects': subject_stats
    }), 200

@blu.route('/admin/export-quiz-stats', methods=['POST'])
@jwt_required()
@roles_required('admin')
def export_quiz_stats():
    """Export quiz statistics (admin only)"""
    data = request.get_json() or {}
    
    # Optional filter parameters
    filters = {
        'subject_id': data.get('subject_id'),
        'chapter_id': data.get('chapter_id'),
        'quiz_id': data.get('quiz_id'),
        'date_from': data.get('date_from'),
        'date_to': data.get('date_to')
    }
    
    # Import inside the function to avoid circular imports
    from backend.tasks import export_quiz_stats_task
    
    # Submit task to background worker
    task = export_quiz_stats_task.delay(admin_id=get_jwt_identity(), filters=filters)
    
    return jsonify({
        'message': 'Export request submitted successfully. You will be notified when it is ready.',
        'task_id': str(task.id)
    }), 202

@blu.route('/stats/subject-performance', methods=['GET'])
@jwt_required()
def get_subject_performance():
    """Get performance statistics by subject"""
    subject_id = request.args.get('subject_id')
    
    # Base query
    query = Score.query.filter_by(user_id=get_jwt_identity())
    
    # Join with quiz and chapter to get subject info
    query = query.join(Quiz).join(Chapter)
    
    # Filter by subject if requested
    if subject_id:
        query = query.filter(Chapter.subject_id == subject_id)
    
    # Get all scores
    scores = query.all()
    
    if not scores:
        return jsonify({
            'message': 'No quiz attempts found for the specified criteria',
            'performance': []
        }), 200
    
    # Group scores by subject
    subject_performance = {}
    
    for score in scores:
        subject_id = score.quiz.chapter.subject.id
        subject_name = score.quiz.chapter.subject.name
        
        if subject_id not in subject_performance:
            subject_performance[subject_id] = {
                'id': subject_id,
                'name': subject_name,
                'attempts': 0,
                'total_score': 0,
                'average': 0,
                'chapters': {}
            }
        
        # Update subject stats
        subject_performance[subject_id]['attempts'] += 1
        subject_performance[subject_id]['total_score'] += score.percentage
        
        # Update chapter stats
        chapter_id = score.quiz.chapter.id
        chapter_name = score.quiz.chapter.name
        
        if chapter_id not in subject_performance[subject_id]['chapters']:
            subject_performance[subject_id]['chapters'][chapter_id] = {
                'id': chapter_id,
                'name': chapter_name,
                'attempts': 0,
                'total_score': 0,
                'average': 0
            }
        
        subject_performance[subject_id]['chapters'][chapter_id]['attempts'] += 1
        subject_performance[subject_id]['chapters'][chapter_id]['total_score'] += score.percentage
    
    # Calculate averages
    for subject_id in subject_performance:
        subject = subject_performance[subject_id]
        subject['average'] = round(subject['total_score'] / subject['attempts'], 2)
        
        # Convert chapters dict to list and calculate averages
        chapter_list = []
        for chapter_id, chapter in subject['chapters'].items():
            chapter['average'] = round(chapter['total_score'] / chapter['attempts'], 2)
            chapter_list.append(chapter)
        
        subject['chapters'] = sorted(chapter_list, key=lambda x: x['name'])
    
    # Return as a list sorted by subject name
    result = sorted(list(subject_performance.values()), key=lambda x: x['name'])
    
    return jsonify(result), 200

@blu.route('/')
def index():
    """Root route - publicly accessible."""
    return jsonify({
        'message': 'Welcome to the Exam Portal API',
        'status': 'online',
        'version': '1.0'
    }), 200

@blu.route('/auth-test')
def auth_test():
    """Test authentication status using both JWT and custom token verification."""
    # Try JWT first
    auth_header = request.headers.get('Authorization')
    user = None
    token_info = None
    
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1].strip()
        try:
            # First try JWT
            from flask_jwt_extended import decode_token as jwt_decode
            payload = jwt_decode(token)
            user_id = payload['sub']
            from backend.models import User
            user = User.query.get(user_id)
            token_info = payload
        except Exception as e:
            # If JWT fails, try custom token
            from backend.utils import verify_custom_token, decode_token
            user = verify_custom_token(token)
            token_info = decode_token(token) if token else None
    
    if user:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'roles': [role.name for role in user.roles]
            }
        }), 200
    
    return jsonify({
        'authenticated': False,
        'message': 'Invalid or missing token',
        'token_info': token_info
    }), 401

@blu.route('/debug-token')
def debug_token():
    """Debug endpoint to check token details"""
    token = None
    auth_header = request.headers.get('Authorization')
    
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1].strip()
    
    # Try to decode the token if present
    decoded_token = None
    if token:
        try:
            from flask_jwt_extended import decode_token as jwt_decode_token
            decoded_token = jwt_decode_token(token)
        except Exception as e:
            decoded_token = {'error': str(e)}
    
    # Add Flask-Security version info
    import flask_security
    
    return jsonify({
        'token_received': bool(token),
        'token_value': token[:10] + '...' if token else None,
        'token_decoded': decoded_token,
        'headers': dict(request.headers),
        'flask_security_version': getattr(flask_security, '__version__', 'unknown'),
        'user_agent': request.user_agent.string,
        'endpoint': request.endpoint,
        'method': request.method,
        'app_config': {
            'SECURITY_TOKEN_AUTHENTICATION_HEADER': current_app.config.get('SECURITY_TOKEN_AUTHENTICATION_HEADER'),
            'SECURITY_TOKEN_MAX_AGE': str(current_app.config.get('SECURITY_TOKEN_MAX_AGE')),
            'JWT_AUTH_HEADER_PREFIX': current_app.config.get('JWT_HEADER_TYPE', 'Bearer')
        }
    }), 200

@blu.errorhandler(401)
def unauthorized_error(error):
    """Handle authentication errors."""
    return jsonify({
        'error': 'Authentication required',
        'message': 'You must provide a valid authentication token',
        'help': 'Ensure your token is valid and properly formatted in the Authentication-Token header'
    }), 401

# Add a test endpoint to create a student user for testing
@blu.route('/test/create-student', methods=['POST'])
def create_test_student():
    """Create a test student user with known credentials (for testing only)"""
    if not current_app.debug:
        return jsonify({"message": "This endpoint is only available in debug mode"}), 403
        
    data = request.get_json() or {}
    email = data.get('email', f'test_student_{int(time.time())}@example.com')
    password = data.get('password', 'password123')
    
    # Log the creation attempt
    current_app.logger.debug(f"Creating test student with email: {email}")
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists with this email'}), 409
    
    # Create student user
    student_user = User(
        email=email,
        full_name=data.get('full_name', 'Test Student'),
        qualification=data.get('qualification', 'Test'),
        dob=datetime.strptime(data.get('dob', '2000-01-01'), '%Y-%m-%d').date(),
        active=True
    )
    student_user.set_password(password)
    
    # Add student role
    student_role = Role.query.filter_by(name='student').first()
    if not student_role:
        student_role = Role(name='student', description='Student role')
        db.session.add(student_role)
        db.session.commit()  # Commit to ensure the role ID is generated
        current_app.logger.debug("Created new student role")
    
    # Make sure we don't duplicate the role
    if student_role not in student_user.roles:
        student_user.roles.append(student_role)
    
    db.session.add(student_user)
    
    try:
        db.session.commit()
        current_app.logger.debug(f"Successfully created student user {email} with role {student_role.name}")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating student: {str(e)}")
        return jsonify({'message': f'Error creating student: {str(e)}'}), 500
    
    return jsonify({
        'message': 'Test student created successfully',
        'email': email,
        'password': password,
        'roles': [role.name for role in student_user.roles]
    }), 201

# Add this debug endpoint only for development mode
@blu.route('/debug/student-credentials', methods=['GET'])
def get_test_student_credentials():
    """Get credentials for a valid student account (for testing purposes only)"""
    if not current_app.debug:
        return jsonify({"message": "This endpoint is only available in debug mode"}), 403
        
    # Find a student user
    student_role = Role.query.filter_by(name='student').first()
    if not student_role:
        return jsonify({"message": "No student role found"}), 404
        
    student_user = User.query.filter(User.roles.contains(student_role)).first()
    if not student_user:
        return jsonify({"message": "No student users found"}), 404
    
    # Create a new password for the student that we can use for testing
    new_password = "student123"
    student_user.set_password(new_password)
    db.session.commit()
    
    return jsonify({
        "email": student_user.email,
        "password": new_password,
        "full_name": student_user.full_name
    }), 200

# Add debug endpoint to reset admin password
@blu.route('/debug/reset-admin', methods=['GET'])
def reset_admin_password():
    """Reset the admin password for testing (only in debug mode)"""
    if not current_app.debug:
        return jsonify({"message": "This endpoint is only available in debug mode"}), 403
    
    admin_email = current_app.config.get('ADMIN_EMAIL', 'admin@exam.com')
    admin_user = User.query.filter_by(email=admin_email).first()
    
    if not admin_user:
        return jsonify({"message": "Admin user not found"}), 404
    
    # Set known password for testing
    admin_password = "admin123"
    admin_user.set_password(admin_password)
    db.session.commit()
    
    return jsonify({
        "message": "Admin password reset successfully",
        "email": admin_email,
        "password": admin_password
    }), 200

# Backend Jobs Endpoints

@blu.route('/jobs/trigger-reminder', methods=['POST'])
@jwt_required()
@roles_required('admin')
def trigger_reminder():
    """Manually trigger the daily reminder job"""
    from backend.tasks import send_daily_reminders
    
    try:
        # Start the task asynchronously
        task = send_daily_reminders.delay()
        
        return jsonify({
            'status': 'success',
            'task_id': task.id,
            'message': 'Daily reminder job has been triggered'
        }), 202
    except Exception as e:
        current_app.logger.error(f"Error triggering reminder job: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to trigger job: {str(e)}"
        }), 500

@blu.route('/jobs/trigger-monthly-report', methods=['POST'])
@jwt_required()
@roles_required('admin')
def trigger_monthly_report():
    """Manually trigger the monthly report generation job"""
    from backend.tasks import send_monthly_reports
    
    try:
        # Start the task asynchronously
        task = send_monthly_reports.delay()
        
        return jsonify({
            'status': 'success',
            'task_id': task.id,
            'message': 'Monthly report job has been triggered'
        }), 202
    except Exception as e:
        current_app.logger.error(f"Error triggering monthly report job: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to trigger job: {str(e)}"
        }), 500

# Test endpoint for Celery
@blu.route('/jobs/test-celery', methods=['GET'])
def test_celery():
    """Simple test endpoint to verify Celery task execution"""
    # Import from the celery_app directly
    from backend.celery_app import test_celery as test_task
    
    try:
        # Start the task asynchronously
        task = test_task.delay()
        
        # Wait for a short period for the task to complete
        from time import sleep
        sleep(1)
        
        # Get the task result
        result = task.get(timeout=3)
        
        return jsonify({
            'status': 'success',
            'task_id': task.id,
            'result': result,
            'message': 'Test task executed successfully'
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error in test_celery endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Error executing test task: {str(e)}"
        }), 500

# Add the following report-related endpoints near other API endpoints

# =============================================
# Report Routes
# =============================================

@blu.route('/reports', methods=['GET'])
@jwt_required()
@roles_required('admin')
def get_reports():
    """Get all reports for admin"""
    user_id = get_jwt_identity()
    
    # Get all reports from Redis
    reports = get_all_reports(limit=50)
    
    return jsonify({
        'status': 'success',
        'reports': reports
    })

@blu.route('/reports/user', methods=['GET'])
@jwt_required()
def get_user_reports_api():
    """Get reports for the current user"""
    user_id = get_jwt_identity()
    
    # Get user's reports from Redis
    reports = get_user_reports(user_id, limit=20)
    
    return jsonify({
        'status': 'success',
        'reports': reports
    })

@blu.route('/reports/generate', methods=['POST'])
@jwt_required()
@roles_required('admin')
def generate_report():
    """Generate a new report"""
    user_id = get_jwt_identity()
    
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided'}), 400
    
    report_type = data.get('report_type')
    if not report_type:
        return jsonify({'status': 'error', 'message': 'Report type is required'}), 400
    
    # Create report entry in Redis
    report_data = {
        'user_id': user_id,
        'report_type': report_type,
        'name': data.get('name', f"{report_type.replace('_', ' ').title()} Report"),
        'filters': data.get('filters', {}),
        'status': 'pending'
    }
    
    report_id = create_report(report_data)
    
    if not report_id:
        return jsonify({
            'status': 'error',
            'message': 'Failed to create report'
        }), 500
    
    # Start the appropriate Celery task based on report_type
    if report_type == 'user_activity':
        from backend.tasks import generate_user_activity_report_func
        task = generate_user_activity_report_func.delay(report_id, user_id, data.get('filters'))
    elif report_type == 'quiz_performance':
        from backend.tasks import generate_quiz_performance_report_func
        task = generate_quiz_performance_report_func.delay(report_id, user_id, data.get('filters'))
    elif report_type == 'subject_analytics':
        from backend.tasks import generate_subject_analytics_report_func
        task = generate_subject_analytics_report_func.delay(report_id, user_id, data.get('filters'))
    elif report_type == 'monthly_summary':
        from backend.tasks import generate_monthly_summary_report_func
        task = generate_monthly_summary_report_func.delay(report_id, user_id, data.get('filters'))
    else:
        return jsonify({
            'status': 'error',
            'message': f'Unknown report type: {report_type}'
        }), 400
    
    # Update report with task ID
    update_report_status(report_id, 'pending', {'task_id': task.id})
    
    return jsonify({
        'status': 'success',
        'message': 'Report generation started',
        'report_id': report_id,
        'task_id': task.id
    })

@blu.route('/reports/<report_id>', methods=['GET'])
@jwt_required()
def get_report_api(report_id):
    """Get details for a specific report"""
    user_id = get_jwt_identity()
    
    # Get report from Redis
    report = get_report(report_id)
    
    if not report:
        return jsonify({
            'status': 'error',
            'message': 'Report not found'
        }), 404
    
    # Check if the user is authorized to view this report
    user_roles = get_jwt().get('roles', [])
    is_admin = any(role == 'admin' for role in user_roles)
    
    if not is_admin and report.get('user_id') != user_id:
        return jsonify({
            'status': 'error',
            'message': 'You are not authorized to view this report'
        }), 403
    
    return jsonify({
        'status': 'success',
        'report': report
    })

@blu.route('/reports/<report_id>', methods=['DELETE'])
@jwt_required()
def delete_report_api(report_id):
    """Delete a report"""
    user_id = get_jwt_identity()
    
    # Get report from Redis
    report = get_report(report_id)
    
    if not report:
        return jsonify({
            'status': 'error',
            'message': 'Report not found'
        }), 404
    
    # Check if the user is authorized to delete this report
    user_roles = get_jwt().get('roles', [])
    is_admin = any(role == 'admin' for role in user_roles)
    
    if not is_admin and report.get('user_id') != user_id:
        return jsonify({
            'status': 'error',
            'message': 'You are not authorized to delete this report'
        }), 403
    
    # Delete the report
    success = delete_report(report_id)
    
    if not success:
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete report'
        }), 500
    
    return jsonify({
        'status': 'success',
        'message': 'Report deleted successfully'
    })

@blu.route('/reports/download/<filename>', methods=['GET'])
@jwt_required()
def download_report(filename):
    """Download a report file"""
    # Sanitize filename to prevent directory traversal attacks
    filename = os.path.basename(filename)
    
    # Set the path to the exports folder
    exports_folder = current_app.config.get('EXPORT_FOLDER', 'exports')
    filepath = os.path.join(exports_folder, filename)
    
    if not os.path.exists(filepath):
        return jsonify({
            'status': 'error',
            'message': 'File not found'
        }), 404
    
    # Determine content type based on file extension
    extension = os.path.splitext(filename)[1].lower()
    content_type = {
        '.csv': 'text/csv',
        '.pdf': 'application/pdf',
        '.html': 'text/html',
        '.txt': 'text/plain'
    }.get(extension, 'application/octet-stream')
    
    return send_file(
        filepath,
        mimetype=content_type,
        as_attachment=True,
        download_name=filename
    )

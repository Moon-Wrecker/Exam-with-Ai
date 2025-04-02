from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

# Import db from database.py
from .database import db

# Security Models
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('users.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('roles.id')))

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    active = db.Column(db.Boolean(), default=True)
    confirmed_at = db.Column(db.DateTime())
    full_name = db.Column(db.String(255))
    qualification = db.Column(db.String(255))
    dob = db.Column(db.Date)
    roles = db.relationship('Role', secondary=roles_users, 
                           backref=db.backref('users', lazy='dynamic'))
    scores = db.relationship('Score', back_populates='user', 
                            cascade='all, delete-orphan')

    def set_password(self, password):
        """Set the password using secure hashing"""
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password, password)
    
    def is_authenticated(self):
        return True
        
    def is_active(self):
        return self.active
        
    def is_anonymous(self):
        return False
        
    def get_id(self):
        return str(self.id)

# Application Models
class Subject(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    chapters = db.relationship('Chapter', back_populates='subject', 
                              cascade='all, delete-orphan')

class Chapter(db.Model):
    __tablename__ = 'chapters'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'))
    subject = db.relationship('Subject', back_populates='chapters')
    quizzes = db.relationship('Quiz', back_populates='chapter', 
                             cascade='all, delete-orphan')

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapters.id'))
    date_of_quiz = db.Column(db.Date, nullable=False)
    time_duration = db.Column(db.Integer, nullable=False)  # Minutes
    remarks = db.Column(db.Text)
    chapter = db.relationship('Chapter', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz',
                               cascade='all, delete-orphan')
    scores = db.relationship('Score', back_populates='quiz',
                            cascade='all, delete-orphan')

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'))
    question_statement = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255))
    option4 = db.Column(db.String(255))
    correct_option = db.Column(db.Integer, nullable=False)
    quiz = db.relationship('Quiz', back_populates='questions')

class Score(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_scored = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer, nullable=True)  # Time taken in seconds
    user = db.relationship('User', back_populates='scores')
    quiz = db.relationship('Quiz', back_populates='scores')

    @property
    def percentage(self):
        if self.total_questions == 0:
            return 0.0
        return round((self.total_scored / self.total_questions) * 100, 2)

# Simple user datastore replacement - not using Flask-Security
class SimpleUserDatastore:
    def __init__(self, db, user_model, role_model):
        self.db = db
        self.user_model = user_model
        self.role_model = role_model
    
    def find_user(self, **kwargs):
        return self.user_model.query.filter_by(**kwargs).first()
    
    def find_role(self, name):
        return self.role_model.query.filter_by(name=name).first()
    
    def create_user(self, **kwargs):
        password = kwargs.pop('password', None)
        user = self.user_model(**kwargs)
        if password:
            user.set_password(password)
        self.db.session.add(user)
        return user
    
    def add_role_to_user(self, user, role):
        if not user.roles:
            user.roles = []
        if role not in user.roles:
            user.roles.append(role)
    
    def find_or_create_role(self, name, description=None):
        role = self.find_role(name)
        if not role:
            role = self.role_model(name=name, description=description)
            self.db.session.add(role)
            self.db.session.commit()
        return role

# Initialize user datastore
user_datastore = SimpleUserDatastore(db, User, Role)
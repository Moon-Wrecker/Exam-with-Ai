# Exam with AI 🎓

A comprehensive AI-powered examination and quiz management platform built with Flask, featuring automated quiz generation, real-time scoring, and advanced analytics.

## 📹 Demo Video

Watch the complete walkthrough of the application:

[Demo Video](https://drive.google.com/file/d/12o6XeaYKu-J_LutkCe6oJ2n5AD8uFhvO/view?usp=sharing)

## ✨ Features

### For Students
- 📝 Take AI-generated quizzes on various subjects
- ⏱️ Timed examination mode
- 📊 View detailed score reports and analytics
- 📈 Track performance over time
- 🎯 Chapter-wise quiz selection

### For Administrators
- 👥 User management with role-based access control
- 📚 Subject and chapter management
- ❓ Question bank management
- 🤖 AI-powered quiz generation
- 📊 Export quiz data and analytics
- 📧 Email notifications and reports
- 📅 Scheduled tasks with Celery

## 🛠️ Tech Stack

### Backend
- **Flask** - Web framework
- **SQLAlchemy** - ORM for database operations
- **Flask-Security-Too** - User authentication and authorization
- **Celery** - Distributed task queue for background jobs
- **Redis** - Message broker and caching
- **Flask-JWT-Extended** - JWT token authentication
- **Flask-Mail** - Email notifications

### Key Libraries
- **Pandas & NumPy** - Data analysis and export
- **Flask-CORS** - Cross-origin resource sharing
- **Flask-Caching** - Response caching
- **Gunicorn** - WSGI HTTP server

## 📋 Prerequisites

- Python 3.8+
- Redis Server
- SQLite (default) or PostgreSQL/MySQL

## 🚀 Installation

1. **Clone the repository**
```bash
git clone https://github.com/Moon-Wrecker/Exam-with-Ai.git
cd Exam-with-Ai
```

2. **Create a virtual environment**
```bash
python -m venv lenv
source lenv/bin/activate  # On Windows: lenv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**

Create a `.env` file in the root directory with the following variables:
```env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
SECURITY_PASSWORD_SALT=your-password-salt-here
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123

# Database
DATABASE_URL=sqlite:///instance/quiz_master.db

# Redis
REDIS_URL=redis://localhost:6379/0

# Mail Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-password
```

5. **Initialize the database**
```bash
flask init-db
flask create-admin
```

6. **Start Redis server**
```bash
redis-server
```

## 🏃 Running the Application

### Option 1: Using the start script (Recommended)
```bash
bash start_services.sh
```

### Option 2: Manual startup

**Terminal 1 - Flask Application:**
```bash
python app.py
```

**Terminal 2 - Celery Worker:**
```bash
celery -A app.celery worker --loglevel=info
```

**Terminal 3 - Celery Beat (for scheduled tasks):**
```bash
celery -A app.celery beat --loglevel=info
```

The application will be available at `http://localhost:1406`

## 📁 Project Structure

```
Exam-with-Ai/
├── app.py                 # Main application entry point
├── backend/
│   ├── __init__.py       # Flask app factory
│   ├── api.py            # REST API endpoints
│   ├── models.py         # Database models
│   ├── tasks.py          # Celery background tasks
│   ├── utils.py          # Utility functions
│   ├── config.py         # Configuration settings
│   └── templates/        # Email templates
├── instance/             # Instance-specific files (database)
├── requirements.txt      # Python dependencies
├── start_services.sh     # Service startup script
└── README.md            # This file
```

## 🔑 Default Credentials

**Admin Account:**
- Email: `admin@example.com`
- Password: `admin123`

⚠️ **Important:** Change these credentials after first login!

## 🌟 Key Features Explained

### AI-Powered Quiz Generation
The platform can automatically generate quizzes based on configured subjects and chapters, leveraging AI algorithms to create diverse question sets.

### Role-Based Access Control
- **Students**: Can take quizzes, view scores, and track progress
- **Admins**: Full system access including user management, content creation, and analytics

### Background Task Processing
Celery handles time-consuming operations like:
- Generating quiz reports
- Sending bulk emails
- Processing analytics data
- Scheduled quiz reminders

### Comprehensive Analytics
Track student performance with:
- Score distribution
- Time taken per quiz
- Chapter-wise performance
- Historical trends

## 🔧 Configuration

Key configuration options in `backend/config.py`:
- Database URI
- Redis connection
- JWT token settings
- Mail server settings
- Session configuration
- File upload limits

## 📊 API Endpoints

The application provides RESTful API endpoints under `/api/`:
- User authentication (`/api/auth/`)
- Quiz management (`/api/quizzes/`)
- Subject and chapter operations
- Score tracking and analytics
- Admin operations

## 🐛 Troubleshooting

### Redis Connection Error
Ensure Redis server is running:
```bash
redis-cli ping  # Should return "PONG"
```

### Database Migration Issues
Reset the database:
```bash
flask migrate
```

### Port Already in Use
Change the port in `app.py`:
```python
app.run(debug=True, port=YOUR_PORT)
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available for educational purposes.

## 👤 Author

**Moon-Wrecker**
- GitHub: [@Moon-Wrecker](https://github.com/Moon-Wrecker)

## 🙏 Acknowledgments

- Built with Flask and modern web technologies
- Inspired by the need for intelligent examination systems
- Thanks to all contributors and users

---

For more information or support, please open an issue on GitHub.
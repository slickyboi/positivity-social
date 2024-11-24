# Positivity Social

A social media platform that promotes positive interactions and uplifting content. Built with Flask and React.

## Features

- User authentication and profiles
- Positive-only posting system with sentiment analysis
- Multi-image upload with advanced editing capabilities
- Real-time notifications
- Content moderation and reporting system
- Admin dashboard with analytics
- User profile customization
- Secure file uploads to S3
- Rate limiting and security features
- Email notifications
- Responsive design

## Prerequisites

- Python 3.8+
- Node.js 14+
- PostgreSQL
- Redis
- AWS Account (for S3 storage)

## Setup

### Environment Setup

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Update the `.env` file with your configuration:
- Generate a secure SECRET_KEY
- Set up PostgreSQL and update DATABASE_URL
- Configure AWS credentials
- Set up email settings
- Add Sentry DSN (optional)

### Backend Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
flask db upgrade
```

4. Start Redis server:
```bash
redis-server
```

5. Start Celery worker:
```bash
celery -A app.celery worker --loglevel=info
```

6. Run the Flask server:
```bash
python app.py
```

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

## Production Deployment

1. Set environment variables:
- Set FLASK_ENV=production
- Configure secure SECRET_KEY
- Set up production database URL
- Configure AWS credentials
- Set up email service
- Add Sentry DSN

2. Build frontend:
```bash
cd frontend
npm run build
```

3. Run with gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Security Features

- HTTPS enforcement
- CSRF protection
- Rate limiting
- Secure session handling
- Input validation
- File upload validation
- SQL injection prevention
- XSS protection
- Secure password hashing

## Monitoring

- Sentry integration for error tracking
- Custom logging system
- Performance monitoring
- User activity tracking
- Admin dashboard with analytics

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

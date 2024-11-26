import os
from flask import Flask, request, jsonify, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
from flask_mail import Mail, Message
from flask_migrate import Migrate
from textblob import TextBlob
import jwt
import datetime
import bcrypt
from dotenv import load_dotenv
import magic
from PIL import Image
import uuid
import boto3
import redis
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from celery import Celery
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

# Initialize Sentry
sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN'),
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0
)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')

# Security middleware
Talisman(app, force_https=True)
csrf = SeaSurf(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app
)

# CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": [os.getenv('FRONTEND_URL')],
        "supports_credentials": True
    }
})

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Redis configuration
redis_client = redis.from_url(os.getenv('REDIS_URL'))

# S3 Configuration
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_REGION')
)

def upload_file_to_s3(file, acl="public-read"):
    try:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}-{filename}"
        
        s3_client.upload_fileobj(
            file,
            os.getenv('S3_BUCKET'),
            unique_filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )

        # Generate the URL of the uploaded file
        return f"https://{os.getenv('S3_BUCKET')}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{unique_filename}"
    except Exception as e:
        print(f"Error uploading file to S3: {str(e)}")
        return None

# Celery configuration
celery = Celery(
    app.name,
    broker=os.getenv('REDIS_URL'),
    backend=os.getenv('REDIS_URL')
)

# Mail configuration
mail = Mail(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)

# Logging configuration
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/positivity_social.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Positivity Social startup')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('Like', backref='post', lazy=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bio = db.Column(db.String(500))
    avatar_url = db.Column(db.String(255))
    preferences = db.Column(db.JSON)
    last_active = db.Column(db.DateTime)

# Celery tasks
@celery.task
def send_email_notification(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)

@celery.task
def process_image_async(image_data, filename):
    try:
        # Image processing logic
        return {'success': True, 'url': f's3_url_here/{filename}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# Rate limiting decorators
def user_rate_limit():
    return limiter.limit("100/minute")

# Authentication decorator with rate limiting
def auth_required(f):
    @user_rate_limit()
    @token_required
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'error': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Check sentiment function
def check_sentiment(text):
    """Check if the text has positive sentiment"""
    analysis = TextBlob(text)
    return analysis.sentiment.polarity > 0

# Allowed file function
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Process image function
def process_image(file):
    # Generate unique filename
    filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Save and process image
    img = Image.open(file)
    
    # Convert to RGB if necessary
    if img.mode in ('RGBA', 'P'):
        img = img.convert('RGB')
    
    # Resize if larger than max size while maintaining aspect ratio
    if img.size[0] > 1920 or img.size[1] > 1080:
        img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
    
    # Save optimized image
    img.save(filepath, optimize=True, quality=85)
    return filename

# Route handlers
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    user = User(username=data['username'], email=data['email'], password_hash=hashed)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/posts', methods=['GET'])
@token_required
def get_posts(current_user):
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return jsonify([{
        'id': post.id,
        'content': post.content,
        'image_url': post.image_path,
        'author': post.author.username,
        'timestamp': post.timestamp,
        'likes': len(post.likes)
    } for post in posts])

@app.route('/api/posts', methods=['POST'])
@token_required
def create_post(current_user):
    try:
        content = request.form.get('content')
        if not content:
            return jsonify({'error': 'Content is required'}), 400

        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                image_url = upload_file_to_s3(file)
                if not image_url:
                    return jsonify({'error': 'Failed to upload image'}), 500

        post = Post(
            content=content,
            image_path=image_url,
            user_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()

        return jsonify({
            'message': 'Post created successfully',
            'post': {
                'id': post.id,
                'content': post.content,
                'image_url': post.image_path,
                'timestamp': post.timestamp.isoformat()
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating post: {str(e)}")
        return jsonify({'error': 'Failed to create post'}), 500

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
def like_post(current_user, post_id):
    existing_like = Like.query.filter_by(
        user_id=current_user.id, 
        post_id=post_id
    ).first()
    
    if existing_like:
        return jsonify({'error': 'Already liked'}), 400
    
    like = Like(user_id=current_user.id, post_id=post_id)
    db.session.add(like)
    db.session.commit()
    
    return jsonify({'message': 'Post liked successfully'}), 201

@app.route('/api/notifications', methods=['GET'])
@auth_required
def get_notifications():
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        read=False
    ).order_by(Notification.created_at.desc()).limit(20).all()
    return jsonify([{
        'id': n.id,
        'message': n.message,
        'type': n.type,
        'created_at': n.created_at.isoformat()
    } for n in notifications])

@app.route('/api/report/<int:post_id>', methods=['POST'])
@auth_required
def report_post(post_id):
    data = request.get_json()
    report = Report(
        reporter_id=current_user.id,
        post_id=post_id,
        reason=data.get('reason')
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({'message': 'Report submitted successfully'})

@app.route('/api/profile', methods=['GET', 'PUT'])
@auth_required
def handle_profile():
    if request.method == 'GET':
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        return jsonify({
            'bio': profile.bio,
            'avatar_url': profile.avatar_url,
            'preferences': profile.preferences
        })
    else:
        data = request.get_json()
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not profile:
            profile = UserProfile(user_id=current_user.id)
        
        profile.bio = data.get('bio', profile.bio)
        profile.preferences = data.get('preferences', profile.preferences)
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = f"avatars/{uuid.uuid4()}{os.path.splitext(file.filename)[1]}"
                s3_client.upload_fileobj(
                    file,
                    os.getenv('AWS_STORAGE_BUCKET_NAME'),
                    filename,
                    ExtraArgs={'ACL': 'public-read'}
                )
                profile.avatar_url = f"https://{os.getenv('AWS_STORAGE_BUCKET_NAME')}.s3.amazonaws.com/{filename}"
        
        db.session.add(profile)
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})

@app.route('/api/admin/reports', methods=['GET'])
@auth_required
def get_reports():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    reports = Report.query.filter_by(status='pending').all()
    return jsonify([{
        'id': r.id,
        'post_id': r.post_id,
        'reporter': User.query.get(r.reporter_id).username,
        'reason': r.reason,
        'created_at': r.created_at.isoformat()
    } for r in reports])

@app.route('/api/admin/stats', methods=['GET'])
@auth_required
def get_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    stats = {
        'total_users': User.query.count(),
        'total_posts': Post.query.count(),
        'total_likes': Like.query.count(),
        'pending_reports': Report.query.filter_by(status='pending').count()
    }
    return jsonify(stats)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))

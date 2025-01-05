from flask import Blueprint, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.config import db, JWT_SECRET_KEY
import jwt
import datetime
import logging
from functools import wraps

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            user = User.query.get(decoded['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 404
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 400

    try:
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        token = jwt.encode(
            {
                'user_id': new_user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            },
            JWT_SECRET_KEY,
            algorithm='HS256'
        )
        
        return jsonify({
            'message': 'User created successfully',
            'token': token,
            'user': {
                'id': str(new_user.id),
                'username': new_user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            },
            JWT_SECRET_KEY,
            algorithm='HS256'
        )
        
        return jsonify({
            'token': token,
            'user': {
                'id': str(user.id),
                'username': user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
            }
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/validate', methods=['GET'])
def validate_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user = User.query.get(decoded['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'valid': True,
            'user': {
                'id': str(user.id),
                'username': user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={user.username}"
            }
        }), 200
    except:
        return jsonify({'error': 'Invalid token'}), 401

@auth_bp.route('/user', methods=['GET'])
@token_required
def get_user(current_user):
    return jsonify({
        'user': {
            'id': str(current_user.id),
            'username': current_user.username,
            'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={current_user.username}"
        }
    }), 200

@auth_bp.route('/update-profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    
    try:
        if data.get('currentPassword'):
            if not check_password_hash(current_user.password, data['currentPassword']):
                return jsonify({'error': 'Current password is incorrect'}), 400
                
            if data.get('newPassword'):
                current_user.password = generate_password_hash(data['newPassword'])
                
        if data.get('username'):
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'error': 'Username already taken'}), 400
                
            current_user.username = data['username']
            
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': {
                'id': str(current_user.id),
                'username': current_user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={current_user.username}"
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 
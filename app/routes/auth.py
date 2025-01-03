from flask import Blueprint, request, jsonify, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.config import db
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:5174")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

def create_cors_response(data, status_code=200):
    response = jsonify(data)
    response.status_code = status_code
    return response

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        return create_cors_response({
            'user': {
                'id': str(user.id),
                'username': user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
            }
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return create_cors_response({})
        
    logger.info('Received registration request')
    data = request.get_json()
    logger.debug(f'Registration data received: {data}')
    
    try:
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            logger.warning('Missing required fields')
            return jsonify({'error': 'Missing required fields'}), 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            logger.warning(f'Username {username} already exists')
            return jsonify({'error': 'Username already exists'}), 400

        logger.info(f'Creating new user: {username}')
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            logger.info(f'User {username} created successfully')
        except Exception as db_error:
            logger.error(f'Database error: {str(db_error)}')
            db.session.rollback()
            return jsonify({'error': 'Database error', 'details': str(db_error)}), 500

        return create_cors_response({
            'message': 'User created successfully',
            'user': {
                'id': str(new_user.id),
                'username': new_user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
            }
        }, 201)
        
    except Exception as e:
        logger.error(f'Error during registration: {str(e)}', exc_info=True)
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

@auth_bp.route('/user', methods=['GET'])
def get_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(user_id)
    if not user:
        session.pop('user_id', None)
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'user': {
            'id': str(user.id),
            'username': user.username,
            'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={user.username}"
        }
    }), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@auth_bp.route('/test', methods=['GET'])
def test_connection():
    logger.info('Testing database connection')
    try:
        User.query.first()
        logger.info('Database connection test successful')
        return jsonify({
            'message': 'Database connection successful',
            'status': 'success'
        }), 200
    except Exception as e:
        logger.error(f'Database connection test failed: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'Database connection failed: {str(e)}',
            'status': 'error'
        }), 500 

@auth_bp.route('/test-auth', methods=['GET', 'OPTIONS'])
def test_auth():
    logger.info('Testing auth endpoint')
    return create_cors_response({
        'status': 'ok',
        'message': 'Auth test successful',
        'session': bool(session.get('user_id')),
        'headers': dict(request.headers)
    }) 

@auth_bp.route('/update-profile', methods=['PUT', 'OPTIONS'])
def update_profile():
    if request.method == 'OPTIONS':
        return create_cors_response({})

    logger.info('Received profile update request')
    
    if 'user_id' not in session:
        logger.warning('Unauthorized profile update attempt')
        return jsonify({'error': 'Not authenticated'}), 401
        
    data = request.get_json()
    logger.debug(f'Profile update data received: {data}')
    
    user = User.query.get(session['user_id'])
    if not user:
        logger.warning(f'User not found for id: {session["user_id"]}')
        return jsonify({'error': 'User not found'}), 404
        
    try:
        # Verifica password attuale
        if data.get('currentPassword'):
            if not check_password_hash(user.password, data['currentPassword']):
                logger.warning('Incorrect current password provided')
                return jsonify({'error': 'Current password is incorrect'}), 400
                
            if data.get('newPassword'):
                logger.info('Updating password')
                user.password = generate_password_hash(data['newPassword'])
                
        # Aggiorna username se fornito
        if data.get('username'):
            # Verifica che il nuovo username non sia già in uso
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != user.id:
                logger.warning(f'Username {data["username"]} already taken')
                return jsonify({'error': 'Username already taken'}), 400
                
            logger.info(f'Updating username from {user.username} to {data["username"]}')
            user.username = data['username']
            
        db.session.commit()
        logger.info('Profile updated successfully')
        
        return create_cors_response({
            'message': 'Profile updated successfully',
            'user': {
                'id': str(user.id),
                'username': user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={user.username}"
            }
        })
    except Exception as e:
        logger.error(f'Error updating profile: {str(e)}', exc_info=True)
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 
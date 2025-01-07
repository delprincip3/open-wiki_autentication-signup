from flask import Blueprint, request, jsonify, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.config import db
import logging
import uuid

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        logger.warning("Missing credentials")
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        logger.info(f"Successful login for user {username}")
        
        # Genera un ID di sessione univoco
        session_id = str(uuid.uuid4())
        session['user_id'] = user.id
        session['session_id'] = session_id
        session.permanent = True
        
        response = make_response(jsonify({
            'user': {
                'id': str(user.id),
                'username': user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
            }
        }))
        
        # Imposta il cookie con l'ID di sessione
        response.set_cookie(
            'session_id',
            session_id,
            httponly=True,
            samesite='Lax',
            secure=False,  # Imposta True in produzione
            path='/',
            max_age=7 * 24 * 60 * 60  # 7 giorni in secondi
        )
        
        logger.debug(f"Session after login: {session}")
        logger.debug(f"Cookies in response: {response.headers.get('Set-Cookie')}")
        
        return response, 200
    
    logger.warning(f"Failed login attempt for username: {username}")
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/user', methods=['GET'])
def get_user():
    user_id = session.get('user_id')
    session_id = request.cookies.get('session_id')
    
    logger.debug(f"Current session: {session}")
    logger.debug(f"Session ID from cookie: {session_id}")
    
    if not user_id or not session_id or session_id != session.get('session_id'):
        logger.warning("Invalid session")
        return jsonify({'error': 'Not authenticated'}), 401
        
    user = User.query.get(user_id)
    if not user:
        logger.warning(f"User not found for id: {user_id}")
        session.pop('user_id', None)
        return jsonify({'error': 'User not found'}), 404
        
    logger.info(f"User found: {user.username}")
    return jsonify({
        'user': {
            'id': str(user.id),
            'username': user.username,
            'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={user.username}"
        }
    }), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.delete_cookie('session_id', path='/')
    logger.info("User logged out")
    return response, 200 

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        logger.warning("Missing registration fields")
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter_by(username=username).first():
        logger.warning(f"Registration failed: username {username} already exists")
        return jsonify({'error': 'Username already exists'}), 400

    try:
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f"User {username} registered successfully")
        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': str(new_user.id),
                'username': new_user.username,
                'avatar': f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500 
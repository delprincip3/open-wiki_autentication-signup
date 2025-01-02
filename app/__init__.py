from flask import Flask, request, jsonify
from flask_cors import CORS
from .config import Config, db
import logging

def create_app():
    # Configura il logging più dettagliato
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    
    app = Flask(__name__)
    logger.info('Initializing Flask app...')
    
    # Configurazione dall'oggetto Config
    app.config.from_object(Config)
    
    # Inizializzazione del database
    db.init_app(app)
    logger.info('Database initialized')
    
    # Configurazione CORS più permissiva
    CORS(app, 
         supports_credentials=True,
         resources={
             r"/*": {
                 "origins": [
                     "http://localhost:5174",
                     "http://127.0.0.1:5174",
                     "http://localhost:5001",
                     "http://127.0.0.1:5001"
                 ],
                 "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                 "allow_headers": ["Content-Type", "Authorization"],
                 "expose_headers": ["Content-Range", "X-Content-Range"],
                 "supports_credentials": True
             }
         })
    logger.info('CORS configured')
    
    # Route di test per verificare che il server funzioni
    @app.route('/')
    def home():
        return jsonify({
            'status': 'ok',
            'message': 'Server is running'
        })
    
    # Registrazione delle routes
    from .routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    logger.info('Routes registered')
    
    return app 
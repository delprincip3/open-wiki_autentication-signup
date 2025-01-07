from flask import Flask
from flask_cors import CORS
from .config import Config, db
from datetime import timedelta

def create_app():
    app = Flask(__name__)
    
    # Configurazione dall'oggetto Config
    app.config.from_object(Config)
    
    # Inizializzazione del database
    db.init_app(app)
    
    # Configurazione CORS per supportare i cookie
    CORS(app, 
         supports_credentials=True,
         resources={
             r"/*": {
                 "origins": ["http://localhost:5174"],
                 "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                 "allow_headers": ["Content-Type"],
                 "expose_headers": ["Content-Range", "X-Content-Range", "Set-Cookie"]
             }
         })

    # Configurazione sessione
    app.config.update(
        SECRET_KEY=Config.SECRET_KEY,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=False,  # Imposta True in produzione
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_PATH='/',
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),  # Durata della sessione
        SESSION_COOKIE_NAME='session'  # Nome del cookie di sessione
    )

    # Registrazione delle routes
    from .routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app 
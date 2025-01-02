from flask_sqlalchemy import SQLAlchemy

# Inizializzazione delle estensioni
db = SQLAlchemy()

class Config:
    SECRET_KEY = 'chiave-segreta-di-default'
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:Luigi2005@localhost:3306/openwiki"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configurazioni CORS
    CORS_HEADERS = 'Content-Type'
    SESSION_COOKIE_SECURE = False  # Impostare su True in produzione
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax' 
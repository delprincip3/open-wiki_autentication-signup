from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()

# Definiamo JWT_SECRET_KEY a livello di modulo
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-123')

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-123')
    JWT_SECRET_KEY = JWT_SECRET_KEY  # Lo includiamo anche nella configurazione
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', "mysql+pymysql://root:Luigi2005@localhost:3306/openwiki")
    SQLALCHEMY_TRACK_MODIFICATIONS = False 
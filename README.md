# 🔐 Open Wiki Authentication Service

Questo è il servizio di autenticazione per l'applicazione Open Wiki, implementato con Flask. Gestisce l'autenticazione degli utenti e le sessioni.

## ⚠️ Importante: Componenti Richiesti

Questo è solo uno dei tre componenti necessari per il funzionamento completo dell'applicazione Open Wiki. Per utilizzare l'applicazione completa, è necessario installare e configurare tutti e tre i componenti:

1. **Frontend React** - Per l'interfaccia utente:  
   [@delprincip3/open-wiki_front](https://github.com/delprincip3/open-wiki_front.git)
   - Gestisce l'interfaccia utente
   - Implementa le form di login e registrazione
   - Gestisce il profilo utente
   - Visualizza gli articoli di Wikipedia
   - Porta 5174

2. **Java Middleware** - Per la gestione degli articoli:  
   [@delprincip3/open-wiki_Java-middleware](https://github.com/delprincip3/open-wiki_Java-middleware.git)
   - Gestisce le operazioni sugli articoli
   - Interagisce con l'API di Wikipedia
   - Salva gli articoli nel database
   - Gestisce la ricerca e il filtraggio
   - Porta 8080

3. **Questo Servizio di Autenticazione** - Per la gestione utenti:
   - Gestisce registrazione e login utenti
   - Mantiene le sessioni utente
   - Gestisce l'aggiornamento dei profili
   - Porta 5001

## 🛠️ Tecnologie Utilizzate

- **Backend**:
  - Python 3.12+
  - Flask Framework
  - Flask-SQLAlchemy (ORM)
  - Flask-CORS
  - Werkzeug per la sicurezza

- **Database**:
  - MySQL 8.0+
  - SQLAlchemy per la gestione del DB

- **Sicurezza**:
  - Password hashing con Werkzeug
  - Sessioni sicure con cookie httpOnly
  - CORS configurato per sicurezza

## 🚀 Setup e Installazione

### Prerequisiti
- Python 3.12 o superiore
- MySQL 8.0 o superiore
- pip (Python package installer)
- Git

### 1. Clona il repository 
bash
git clone https://github.com/delprincip3/open-wiki-authentication.git
cd open-wiki-authentication


### 2. Configura l'ambiente virtuale

Crea l'ambiente virtuale
python -m venv venv
Attiva l'ambiente virtuale
Per Windows:
venv\Scripts\activate
Per macOS/Linux:
source venv/bin/activate

### 3. Installa le dipendenze
```bash
pip install -r requirements.txt
```

### 4. Configura il database
```sql
CREATE DATABASE openwiki;
```

### 5. Configura le variabili d'ambiente
Crea un file `.env` nella root del progetto:
```bash
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=mysql+pymysql://username:password@localhost:3306/openwiki
```

### 6. Inizializza il database
```bash
flask db upgrade
```

### 7. Avvia il server
```bash
python run.py
```

## 📝 API Endpoints

### Autenticazione
- `POST /auth/register` - Registrazione nuovo utente
- `POST /auth/login` - Login utente
- `POST /auth/logout` - Logout utente
- `GET /auth/user` - Ottieni dati utente corrente
- `PUT /auth/update-profile` - Aggiorna profilo utente

## 🗄️ Struttura del Progetto
```
backend/
├── app/
│   ├── __init__.py          # Configurazione Flask app
│   ├── config.py            # Configurazioni
│   ├── models.py            # Modelli database
│   └── routes/
│       └── auth.py          # Route autenticazione
├── migrations/              # Migrazioni database
├── .env                     # Variabili ambiente
├── .gitignore
├── requirements.txt         # Dipendenze
└── run.py                  # Entry point
```

## 📧 Contatti

Del Principe - [@github](https://github.com/delprincip3)

Project Link: [https://github.com/delprincip3/open-wiki-authentication](https://github.com/delprincip3/open-wiki-authentication)
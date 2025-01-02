from app import create_app
from app.config import db
import logging

app = create_app()

if __name__ == '__main__':
    print("\n=== Starting Flask Server ===\n")
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=True
    ) 
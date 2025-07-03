from flask import Flask

from anonymous import anonymous_bp
from auth import auth_bp
from config import SERVER_CONFIG
from db import close_db_connection
from files import files_bp

app = Flask(__name__)

app.teardown_appcontext(close_db_connection)

app.register_blueprint(auth_bp)
app.register_blueprint(files_bp)
app.register_blueprint(anonymous_bp)

if __name__ == "__main__":
    app.run(SERVER_CONFIG.host, SERVER_CONFIG.port, debug=True)

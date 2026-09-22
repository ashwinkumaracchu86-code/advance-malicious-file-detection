import os
from flask import Flask
from flask_cors import CORS
from config import Config
from database import init_database
from routes import health_bp, scan_routes_bp, dashboard_bp, report_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, origins=[app.config["FRONTEND_ORIGIN"]])

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "database"), exist_ok=True)

    init_database()

    app.register_blueprint(health_bp)
    app.register_blueprint(scan_routes_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(report_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=False, port=5000)

"""
Flask Main Application Entrypoint
Hosts the REST API and serves the defensive cybersecurity UI.
"""

import os
import sys
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

load_dotenv()
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

def create_app():
    app = Flask(__name__, static_folder=FRONTEND_DIR)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "defensive-cyber-token-2026")
    
    CORS(app)

    # Register API blueprint
    from backend.routes.api import api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    # Serve static frontend pages
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/threat-dashboard.html")
    def threat_dashboard():
        return send_from_directory(FRONTEND_DIR, "threat-dashboard.html")

    @app.route("/threat-details.html")
    def threat_details():
        return send_from_directory(FRONTEND_DIR, "threat-details.html")

    @app.route("/awareness.html")
    def awareness():
        return send_from_directory(FRONTEND_DIR, "awareness.html")

    @app.route("/quiz.html")
    def quiz():
        return send_from_directory(FRONTEND_DIR, "quiz.html")

    @app.route("/css/<path:path>")
    def send_css(path):
        return send_from_directory(os.path.join(FRONTEND_DIR, "css"), path)

    @app.route("/js/<path:path>")
    def send_js(path):
        return send_from_directory(os.path.join(FRONTEND_DIR, "js"), path)

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource or endpoint not found", "status": 404}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error occurred", "status": 500}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    # Bind to 0.0.0.0 so Render and cloud proxies can detect open ports
    host = os.getenv("HOST", "0.0.0.0")
    debug_mode = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    print(f"\n==================================================================")
    print(f" Cybersecurity Awareness & Threat Intelligence Dashboard")
    print(f" Defensive Engine Active at: http://{host}:{port}")
    print(f"==================================================================\n")
    app.run(host=host, port=port, debug=debug_mode)

# app.py
from flask import Flask, jsonify
from config import Config
from extensions import mongo, limiter
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # Allow all origins (OK for dev, restrict in prod)
    CORS(app, supports_credentials=True)

    
    mongo.init_app(app)
    limiter.init_app(app)

    from routes.auth import bp as auth_bp
    from routes.keys import bp as keys_bp
    from routes.manufacturer import bp as manufacturer_bp
    from utils.api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(manufacturer_bp)
    app.register_blueprint(api_bp)

    @app.route("/")
    def health():
        return jsonify({"status":"ok","message":"Product verification API running"})

    return app

app = create_app()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=(Config.FLASK_ENV=="development"))


# app.py
from flask import Flask, jsonify
from config import Config
from extensions import mongo, limiter
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    mongo.init_app(app)
    limiter.init_app(app)

    from auth import bp as auth_bp
    from keys import bp as keys_bp
    from manufacturer import bp as manufacturer_bp
    from api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(manufacturer_bp)
    app.register_blueprint(api_bp)

    @app.route("/")
    def health():
        return jsonify({"status":"ok","message":"Product verification API running"})

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=(Config.FLASK_ENV=="development"))


# Flask==2.3.3
# Flask-PyMongo==2.4.0
# flask-cors==4.0.1
# python-dotenv==1.1.1
# PyJWT==2.8.0
# Werkzeug==2.3.7
# gunicorn==22.1.0
# web3==7.13.0
# flask-limiter==2.8.0
# marshmallow==3.21.0
# marshmallow-sqlalchemy==0.28.0
# Flask==2.3.3
# Flask-PyMongo==2.4.0
# flask-cors==4.0.1
# python-dotenv==1.1.1
# PyJWT==2.8.0
# Werkzeug==2.3.7
# gunicorn==22.1.0
# web3==7.13.0
# flask-limiter==2.8.0
# marshmallow==3.21.0
# marshmallow-sqlalchemy==0.28.0

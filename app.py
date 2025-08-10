from flask import Flask, jsonify
from routes.products import products_bp
from flask_cors import CORS

app = Flask(__name__)
app.register_blueprint(products_bp)
CORS(app)

@app.route("/")
def home():
    return jsonify({"message": "Product API is running"})

if __name__ == "__main__":
    app.run(debug=True)



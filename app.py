from flask import Flask, jsonify
from routes.products import products_bp

app = Flask(__name__)
app.register_blueprint(products_bp)

@app.route("/")
def home():
    return jsonify({"message": "Product API is running"})

if __name__ == "__main__":
    app.run(debug=True)

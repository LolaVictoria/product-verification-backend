from flask import Flask, request, jsonify
from utils.blockchain import register_product, verify_product
from web3 import Web3
from web3 import contract

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    tx_hash = register_product(data['serial'], data['model'], data['manufacturer'])
    return jsonify({"status": "Product Registered", "tx_hash": tx_hash})

@app.route('/verify/<serial>', methods=['GET'])
def verify(serial):
    result = verify_product(serial)
    return jsonify({"product": result})

if __name__ == '__main__':
    app.run(debug=True)

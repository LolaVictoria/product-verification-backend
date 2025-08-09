from flask import Blueprint, request, jsonify
from web3_connection import w3, contract
from config import PRIVATE_KEY

products_bp = Blueprint("products", __name__)

@products_bp.route("/add_product", methods=["POST"])
def add_product():
    data = request.json
    product_id = data.get("product_id")
    product_name = data.get("product_name")

    account = w3.eth.account.from_key(PRIVATE_KEY)
    tx = contract.functions.registerProduct(product_id, product_name).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 2000000,
        'gasPrice': w3.to_wei('10', 'gwei')
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    return jsonify({"tx_hash": tx_hash.hex()})


#verification product
@products_bp.route("/verify_product/<product_id>", methods=["GET"])
def verify_product(product_id):
    try:
        # Call the smart contract's function (read-only)
        product_details = contract.functions.getProduct(product_id).call()

        # If your contract returns empty strings or zero for unregistered products
        if not product_details[0]:  # Assuming first element is product name
            return jsonify({"verified": False, "message": "Product not found"}), 404

        return jsonify({
            "verified": True,
            "product_id": product_id,
            "name": product_details[0],
            "owner": product_details[1],
            "registered_on": product_details[2]  # If you store timestamp
        })
    except Exception as e:
        return jsonify({"verified": False, "error": str(e)}), 500

import json
import os
from web3_connection import Web3
from dotenv import load_dotenv

load_dotenv()

w3 = Web3(Web3.HTTPProvider(os.getenv("PROVIDER_URL")))

with open('contract/contract_abi.json') as f:
    abi = json.load(f)

contract = w3.eth.contract(address=os.getenv("CONTRACT_ADDRESS"), abi=abi)
account = os.getenv("ACCOUNT_ADDRESS")
private_key = os.getenv("PRIVATE_KEY")

def register_product(serial_number, model, manufacturer):
    nonce = w3.eth.get_transaction_count(account)
    tx = contract.functions.registerProduct(serial_number, model, manufacturer).build_transaction({
        'from': account,
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return tx_hash.hex()

def verify_product(serial_number):
    return contract.functions.verifyProduct(serial_number).call()

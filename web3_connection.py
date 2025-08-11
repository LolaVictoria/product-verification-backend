# web3_connection.py
import json
from web3 import Web3
from config import Config

w3 = None; contract = None; account = None
if Config.PROVIDER_URL:
    w3 = Web3(Web3.HTTPProvider(Config.PROVIDER_URL))
    if not w3.is_connected():
        raise RuntimeError("Cannot connect to provider")

    if Config.CONTRACT_ABI_PATH and Config.CONTRACT_ADDRESS:
        with open(Config.CONTRACT_ABI_PATH,"r") as f:
            abi = json.load(f)
        contract = w3.eth.contract(address=Web3.to_checksum_address(Config.CONTRACT_ADDRESS), abi=abi)

    if Config.PRIVATE_KEY:
        account = w3.eth.account.from_key(Config.PRIVATE_KEY)
